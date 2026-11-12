#!/usr/bin/env python3
"""Verify real NFLOG, conntrack and ClickHouse inside an isolated ALT test namespace."""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import time
import threading
import urllib.parse
import urllib.request

STATE = Path('/state')
GATEWAY = '192.0.2.1'
PEER = '192.0.2.2'
CLICKHOUSE = 'http://127.0.0.1:8123'


def run(*args):
    proc = subprocess.run(args, text=True, capture_output=True)
    assert proc.returncode == 0, (args, proc.stderr)
    return proc.stdout


def wait(check, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except OSError:
            pass
        time.sleep(0.25)
    raise AssertionError(f'timed out: {check.__name__}')


def clickhouse(query, body=None):
    url = CLICKHOUSE + '/?' + urllib.parse.urlencode({'query': query, 'wait_end_of_query': 1})
    return urllib.request.urlopen(urllib.request.Request(url, data=body, method='POST'), timeout=4).read()


def pending_events():
    class AgentConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.settimeout(4)
            self.sock.connect(str(STATE / 'agent.sock'))

    with_connection = AgentConnection('localhost', timeout=4)
    try:
        with_connection.request('GET', '/v1/traffic/batch')
        response = with_connection.getresponse()
        assert response.status == 200
        return json.load(response)['events']
    finally:
        with_connection.close()


def close_test_flow():
    # Delete just the fixture tuple and wait for the kernel ACK. Expiration alone
    # relies on the timing of the kernel's background garbage collector.
    def attr(kind, body):
        size = len(body) + 4
        return struct.pack('=HH', size, kind) + body + bytes(-size % 4)

    addresses = attr(1, socket.inet_aton(PEER)) + attr(2, socket.inet_aton(GATEWAY))
    ports = attr(1, bytes([17])) + attr(2, struct.pack('!H', 41000)) + attr(3, struct.pack('!H', 40001))
    original = attr(1 | 0x8000, addresses) + attr(2 | 0x8000, ports)
    body = bytes([socket.AF_INET, 0, 0, 0]) + attr(1 | 0x8000, original)
    request = struct.pack('=IHHII', 16 + len(body), 0x102, 5, 1, 0) + body
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as conn:
        conn.settimeout(4)
        conn.sendto(request, (0, 0))
        reply = conn.recv(4096)
    assert struct.unpack_from('=i', reply, 16)[0] == 0, reply



class SIEMReceiver(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), SIEMHandler, bind_and_activate=False)
        self.server_bind()
        self.messages = []
        self.worker = None

    def start(self):
        self.server_activate()
        self.worker = threading.Thread(target=self.serve_forever, daemon=True)
        self.worker.start()

    def close(self):
        if self.worker:
            self.shutdown()
            self.worker.join()
        self.server_close()


class SIEMHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        while first := self.rfile.read(1):
            length = first
            while (char := self.rfile.read(1)) != b' ':
                if not char or len(length) > 8:
                    raise ValueError('invalid syslog frame length')
                length += char
            message = self.rfile.read(int(length))
            assert len(message) == int(length)
            self.server.messages.append(message.decode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sources-only', action='store_true')
    parser.add_argument('--package', help='RPM path inside the test stand')
    parser.add_argument('--siem', action='store_true')
    parser.add_argument('--no-nflog-conntrack', action='store_true')
    options = parser.parse_args()
    rpmarch = os.uname().machine
    run('rpm', '-Uvh', options.package or f'/work/dist/gfw-0.22.5-1.altp10.{rpmarch}.rpm')
    run('ip', 'netns', 'add', 'traffic-peer')
    run('ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', 'traffic-peer')
    run('ip', 'addr', 'add', GATEWAY + '/24', 'dev', 'lan0')
    run('ip', 'link', 'set', 'lan0', 'up')
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', '-n', 'traffic-peer', 'addr', 'add', PEER + '/24', 'dev', 'peer0')
    run('ip', '-n', 'traffic-peer', 'link', 'set', 'peer0', 'up')
    for key, value in {'nf_conntrack_acct': 1, 'nf_conntrack_events': 1}.items():
        Path('/proc/sys/net/netfilter', key).write_text(str(value))
    run('nft', 'add table inet fixture; add chain inet fixture hooks { type filter hook input priority -5; }; '
        'add rule inet fixture hooks ct state { new, established, related, invalid } counter')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as existing:
        existing.bind((GATEWAY, 40003))
        existing.settimeout(2)
        run('ip', 'netns', 'exec', 'traffic-peer', 'python3', '-c',
            f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'active',('{GATEWAY}',40003))")
        assert existing.recv(64) == b'active'
    agent_log = STATE / 'traffic-agent.log'
    panel_log = STATE / 'traffic-panel.log'
    with agent_log.open('w') as agent_out, panel_log.open('w') as panel_out:
        agent = subprocess.Popen(['/usr/sbin/gfw-agent', '-enable-apply', '-enable-traffic',
                                  '-lan-interface', 'lan0', '-management-port', '8443',
                                  '-state-dir', '/var/lib/gfw-agent', '-socket', str(STATE / 'agent.sock')],
                                 stdout=agent_out, stderr=agent_out)
        panel = subprocess.Popen(['/usr/sbin/gfwd', '-listen', '127.0.0.1:8088',
                                  '-data-dir', '/var/lib/gfw', '-agent-socket', str(STATE / 'agent.sock')],
                                 stdout=panel_out, stderr=panel_out)
        receiver = None
        try:
            wait(lambda: urllib.request.urlopen('http://127.0.0.1:8088/healthz', timeout=1).status == 200)
            token = Path('/var/lib/gfw/admin.token').read_text().strip()

            def api(path, method='GET', body=None, **headers):
                headers.update({'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                request = urllib.request.Request('http://127.0.0.1:8088/api/v1' + path, headers=headers,
                                                 data=None if body is None else json.dumps(body).encode(),
                                                 method=method)
                with urllib.request.urlopen(request, timeout=8) as response:
                    return json.load(response), response.headers

            def status():
                return api('/traffic/status')[0]

            def search(**filters):
                return api('/traffic/events?' + urllib.parse.urlencode({'hours': 1, **filters}))[0]

            def collect_ready():
                runtime = status()['agent']
                return runtime['conntrack'] and runtime['nflog'] and runtime['accounting']

            wait(collect_ready, 8)
            assert status()['agent']['nflog_conntrack'] != options.no_nflog_conntrack
            destination = {'url': 'http://127.0.0.1:18123', 'database': 'gfw_lab',
                           'user': 'gfw_lab', 'password': 'traffic-lab-password'}
            api('/traffic/config', 'PUT', destination)
            wait(lambda: status()['error'])
            draft, headers = api('/config')
            policy = draft['config']
            policy['rules'] = [
                {'id': 'lab-accept', 'name': 'Allow UDP', 'chain': 'input', 'family': 'ipv4', 'protocol': 'udp',
                 'destination_port': 40001, 'action': 'accept', 'enabled': True},
                {'id': 'lab-drop', 'name': 'Drop UDP', 'chain': 'input', 'family': 'ipv4', 'protocol': 'udp',
                 'destination_port': 40002, 'action': 'drop', 'enabled': True},
            ]
            revision = api('/config', 'PUT', policy, **{'If-Match': headers['ETag']})[0]['revision']
            applied, _ = api('/changes/apply', 'POST', {'id': 'traffic-lab', 'revision': revision, 'timeout_seconds': 60})
            assert applied['status'] == 'pending'
            assert api('/changes/traffic-lab/confirm', 'POST', {})[0]['status'] == 'confirmed'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as good, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocked:
                good.bind((GATEWAY, 40001))
                blocked.bind((GATEWAY, 40002))
                good.settimeout(2)
                blocked.settimeout(0.2)
                run('ip', 'netns', 'exec', 'traffic-peer', 'python3', '-c',
                    f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('{PEER}',41000)); "
                    f"s.sendto(b'one',('{GATEWAY}',40001)); [s.sendto(b'two',('{GATEWAY}',40002)) for _ in range(100)]")
                assert good.recv(64) == b'one'
                try:
                    blocked.recv(64)
                    raise AssertionError('drop rule allowed the packet')
                except socket.timeout:
                    pass
            with socket.socket() as lan:
                lan.bind((GATEWAY, 8443))
                lan.listen()
                run('ip', 'netns', 'exec', 'traffic-peer', 'python3', '-c',
                    f"import socket; socket.create_connection(('{GATEWAY}',8443),1).close()")
            def batch_has_traffic():
                events = pending_events()
                kinds = {(e['kind'], e['dport']) for e in events}
                return {('snapshot', 40003), ('rule', 40001), ('rule', 40002), ('new', 40001)} <= kinds

            wait(batch_has_traffic)
            assert status()['agent']['rate_limited'] > 0
            events = pending_events()
            accepted = next(e for e in events if e['rule'] == 'lab-accept')
            dropped = next(e for e in events if e['rule'] == 'lab-drop')
            new = next(e for e in events if e['kind'] == 'new' and e['dport'] == 40001)
            assert new['flow_id']
            expected_flow = '' if options.no_nflog_conntrack else new['flow_id']
            assert accepted['flow_id'] == expected_flow, (accepted, new)
            assert dropped['src'] == PEER and dropped['dst'] == GATEWAY and dropped['sport'] == 41000, dropped
            assert accepted['revision'] == dropped['revision'] == revision
            close_test_flow()
            wait(lambda: any(e['kind'] == 'destroy' and e['flow_id'] == new['flow_id'] and e['packets'] == 1
                             for e in pending_events()))
            print('PASS: traffic filtering and LAN anti-lockout with ClickHouse down, conntrack/NFLOG events on disk', flush=True)
            if options.sources_only:
                return
            wait(lambda: clickhouse('SELECT 1') == b'1\n')
            clickhouse('CREATE DATABASE gfw_lab')
            clickhouse("CREATE USER gfw_lab IDENTIFIED WITH sha256_password BY 'traffic-lab-password'")
            clickhouse('GRANT ALL ON gfw_lab.* TO gfw_lab')
            if options.siem:
                receiver = SIEMReceiver()
                cfg, _ = api('/siem')
                api('/siem', 'PUT', {
                    'revision': cfg['revision'], 'enabled': True, 'address': f'127.0.0.1:{receiver.server_address[1]}',
                    'transport': 'tcp', 'ca_pem': '',
                    'traffic': {
                        'conntrack': ['new', 'destroy'], 'nflog': ['drop'], 'ip': '192.0.2.0/24',
                        'port': 41000, 'protocol': 17, 'rule': 'lab-drop', 'direction': 'input',
                    },
                })
            destination['url'] = CLICKHOUSE
            api('/traffic/config', 'PUT', destination)
            wait(lambda: status()['ready'])
            assert 'password' not in status()['config']
            assert b'traffic-lab-password' not in Path('/var/lib/gfw/traffic/clickhouse').read_bytes()

            def rule_events():
                return search(kind='rule', ip='192.0.2.0/24', proto=17, port=40001, rule='lab-accept', action='accept')

            accept = wait(rule_events)[0]
            drop = wait(lambda: search(kind='rule', port=40002, rule='lab-drop', action='drop'))[0]
            assert accept['revision'] == drop['revision'] == revision
            assert accept['src'] == PEER and accept['dst'] == GATEWAY and accept['flow_id'] == expected_flow, accept
            assert drop['sport'] == 41000 and drop['dport'] == 40002

            def ended():
                return [e for e in search(flow_id=new['flow_id']) if e['kind'] == 'destroy']

            destroy = wait(ended, 45)[0]
            assert destroy['packets'] == 1 and destroy['bytes'] >= 31, destroy
            matched = search(flow_id=new['flow_id'])
            expected_kinds = {'new', 'destroy'} if options.no_nflog_conntrack else {'new', 'rule', 'destroy'}
            assert expected_kinds <= {e['kind'] for e in matched}, matched
            similar = search(kind='flow', ip=PEER, port=40001, proto=17, device=accept['device'])
            assert new['flow_id'] in {event['flow_id'] for event in similar}
            assert search(rule="x' OR 1=1") == []
            assert any(e['kind'] == 'snapshot' for e in search(port=40003))
            wait(lambda: status()['agent']['queued'] == 0)
            count = len(rule_events())
            clickhouse('INSERT INTO gfw_lab.gfw_traffic_v1 FORMAT JSONEachRow',
                       (json.dumps(accept) + '\n').encode())
            assert len(rule_events()) == count
            if receiver:
                def siem_waiting():
                    status = api('/siem')[0]
                    return status['traffic_stats']['queued'] > 0 and status.get('traffic_error')

                wait(siem_waiting)
                receiver.start()

                def got_traffic():
                    return all(any(f'|{event}|' in message for message in receiver.messages)
                               for event in ('gfw.conntrack.new', 'gfw.conntrack.destroy', 'gfw.nflog.drop'))

                wait(got_traffic)
                wait(lambda: api('/siem')[0]['traffic_stats']['queued'] == 0)
                assert any('|gfw.nflog.drop|' in message and 'cs2=lab-drop' in message and
                           'externalId=' + drop['event_id'] in message for message in receiver.messages)
                assert any('|gfw.conntrack.destroy|' in message and 'cs1=' + new['flow_id'] in message
                           for message in receiver.messages)
                assert not any('|gfw.nflog.accept|' in message or '|gfw.conntrack.snapshot|' in message
                               for message in receiver.messages)
                print('PASS: CEF filters and retry after SIEM outage, full traffic remains in ClickHouse', flush=True)
            print('PASS: ClickHouse delivery, parameterized filters, flow/rule correlation, counters and deduplication', flush=True)
        except Exception:
            print(agent_log.read_text(), panel_log.read_text(), sep='\n', flush=True)
            if (STATE / 'agent.sock').exists():
                print(status(), flush=True)
                print([event for event in pending_events() if event['dport'] in (40001, 40002, 40003)], flush=True)
            raise
        finally:
            if receiver:
                receiver.close()
            for proc in (panel, agent):
                proc.terminate()
                proc.wait(timeout=15)


if __name__ == '__main__':
    main()
