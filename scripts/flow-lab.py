#!/usr/bin/env python3
"""Verify actual software flow offload, exclusion and rollback on ALT p10."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:8088'
STATE = Path('/state')
LAN = '192.0.2.1'
WAN = '198.51.100.2'
IPS = '203.0.113.2'
WAN6 = '2001:db8:2::2'
TCP, UDP, LOGGED = 48101, 48102, 48103


def run(*args):
    proc = subprocess.run(args, text=True, capture_output=True)
    assert proc.returncode == 0, (args, proc.stderr)
    return proc.stdout


def wait(check, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, urllib.error.HTTPError):
            pass
        time.sleep(0.1)
    raise AssertionError('Timed out: ' + check.__name__)


def fixture_port(port, namespace, gateway, peer):
    run('ip', 'netns', 'add', namespace)
    run('ip', 'link', 'add', port, 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', namespace)
    run('ip', 'addr', 'add', gateway + '/24', 'dev', port)
    run('ip', 'link', 'set', port, 'up')
    run('ip', '-n', namespace, 'addr', 'add', peer + '/24', 'dev', 'peer0')
    run('ip', '-n', namespace, 'link', 'set', 'peer0', 'up')
    run('ip', '-n', namespace, 'route', 'add', 'default', 'via', gateway)


def ipv6_port(port, namespace, prefix):
    gateway, peer = prefix + '::1', prefix + '::2'
    run('ip', '-6', 'addr', 'add', gateway + '/64', 'dev', port, 'nodad')
    run('ip', '-n', namespace, '-6', 'addr', 'add', peer + '/64', 'dev', 'peer0', 'nodad')
    gw_mac = json.loads(run('ip', '-j', 'link', 'show', port))[0]['address']
    peer_mac = json.loads(run('ip', '-n', namespace, '-j', 'link', 'show', 'peer0'))[0]['address']
    run('ip', '-6', 'neigh', 'replace', peer, 'lladdr', peer_mac, 'nud', 'permanent', 'dev', port)
    run('ip', '-n', namespace, '-6', 'neigh', 'replace', gateway, 'lladdr', gw_mac,
        'nud', 'permanent', 'dev', 'peer0')
    run('ip', '-n', namespace, '-6', 'route', 'add', 'default', 'via', gateway)


ECHO = """
import socket,sys,threading
address, tcp, udp, logged = sys.argv[1], *map(int, sys.argv[2:])
family = socket.AF_INET6 if ":" in address else socket.AF_INET

def serve_udp(port):
    with socket.socket(family,socket.SOCK_DGRAM) as s:
        s.bind((address,port))
        while True:
            data,peer = s.recvfrom(4096)
            s.sendto(data,peer)

for port in (udp,logged):
    threading.Thread(target=serve_udp,args=(port,),daemon=True).start()
with socket.socket(family,socket.SOCK_STREAM) as s:
    s.bind((address,tcp))
    s.listen()
    print('ready',flush=True)
    while True:
        conn,_ = s.accept()
        with conn:
            while True:
                data = conn.recv(4096)
                if not data: break
                conn.sendall(data)
"""

CLIENT = """
import socket,sys
address, port = sys.argv[1], int(sys.argv[2])
family = socket.AF_INET6 if ":" in address else socket.AF_INET
with socket.socket(family,socket.SOCK_DGRAM) as s:
    s.connect((address,port))
    s.settimeout(.35)
    for line in sys.stdin:
        data,count = line.rstrip().split(' ',1)
        payload = data.encode()
        received = 0
        for _ in range(int(count)):
            s.send(payload)
            try:
                if s.recv(4096) == payload: received += 1
            except (socket.timeout, ConnectionRefusedError):
                pass
        print(received,flush=True)
"""


def main():
    run('rpm', '-Uvh', f'/work/dist/gfw-0.22.4-1.altp10.{os.uname().machine}.rpm')
    run('ip', 'link', 'set', 'lo', 'up')
    fixture_port('lan0', 'client', LAN, '192.0.2.2')
    fixture_port('wan0', 'server', '198.51.100.1', WAN)
    fixture_port('ips0', 'inspected', '203.0.113.1', IPS)
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
    ipv6_port('lan0', 'client', '2001:db8:1')
    ipv6_port('wan0', 'server', '2001:db8:2')
    Path('/proc/sys/net/netfilter/nf_conntrack_acct').write_text('1')

    log = STATE / 'flow.log'
    procs = []
    with log.open('w') as output:
        def start(*args, **options):
            child = subprocess.Popen(args, stderr=output, **options)
            procs.append(child)
            return child

        def launch_agent():
            return start('setpriv', '--no-new-privs',
                         '--bounding-set=-all,+net_admin,+chown,+net_bind_service,+net_raw,+setuid,+setgid,+kill,+sys_chroot,+bpf,+perfmon',
                         '/usr/sbin/gfw-agent', '-enable-apply', '-enable-traffic', '-enable-ids',
                         '-lan-interface', 'lan0', '-management-port', '8443',
                         '-state-dir', '/var/lib/gfw-agent', '-socket', str(STATE / 'agent.sock'), stdout=output)

        agent = launch_agent()
        start('/usr/sbin/gfwd', '-listen', '127.0.0.1:8088', '-data-dir', '/var/lib/gfw',
              '-agent-socket', str(STATE / 'agent.sock'), stdout=output)
        try:
            for ns, host in [('server', WAN), ('inspected', IPS), ('server', WAN6)]:
                child = start('ip', 'netns', 'exec', ns, 'python3', '-c', ECHO, host,
                              str(TCP), str(UDP), str(LOGGED), stdout=subprocess.PIPE, text=True)
                assert child.stdout.readline().strip() == 'ready'
            wait(lambda: urllib.request.urlopen(BASE + '/healthz', timeout=1).status == 200)
            key = Path('/var/lib/gfw/admin.token').read_text().strip()

            def api(path, method='GET', body=None, expected=200, **headers):
                headers.update({'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
                request = urllib.request.Request(BASE + '/api/v1' + path, headers=headers, method=method,
                                                 data=None if body is None else json.dumps(body).encode())
                try:
                    response = urllib.request.urlopen(request, timeout=20)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    result = json.load(response)
                    if response.status == 503 and path == '/firewall/flow':
                        raise OSError(result)
                    assert response.status == expected, (path, response.status, result)
                    return result, response.headers

            def flow():
                return api('/firewall/flow')[0]

            def save(config):
                _, headers = api('/config')
                return api('/config', 'PUT', config, **{'If-Match': headers['ETag']})[0]['revision']

            def apply(id, revision):
                return api('/changes/apply', 'POST', {'id': id, 'revision': revision, 'timeout_seconds': 30})[0]

            def udp_client(address, port):
                child = start('ip', 'netns', 'exec', 'client', 'python3', '-c', CLIENT, address, str(port),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
                def send(payload, count):
                    child.stdin.write(f'{payload} {count}\n')
                    child.stdin.flush()
                    return int(child.stdout.readline())
                return send

            def lan_access():
                with socket.socket() as listener:
                    listener.bind((LAN, 8443))
                    listener.listen()
                    run('ip', 'netns', 'exec', 'client', 'python3', '-c',
                        f"import socket; socket.create_connection(('{LAN}',8443),2).close()")

            wait(lambda: flow()['available'])
            config = api('/config')[0]['config']
            for zone in config['zones']:
                if zone['kind'] == 'lan':
                    zone['interfaces'] = ['lan0']
                if zone['kind'] == 'wan':
                    zone['interfaces'] = ['wan0', 'ips0']
            config['flowtable'] = {'interfaces': ['lan0', 'wan0', 'ips0']}
            config['rules'] = [
                {'id': id, 'name': id, 'chain': 'forward', 'family': 'any',
                 'protocol': proto, 'destination_port': port, 'action': 'accept',
                 'enabled': True, 'fast_path': fast, 'log_required': required}
                for id, proto, port, fast, required in [
                    ('accelerated-tcp', 'tcp', TCP, True, False),
                    ('accelerated-udp', 'udp', UDP, True, False),
                    ('mandatory-udp', 'udp', LOGGED, False, True),
                ]
            ]
            config['nat'] = [{'id': 'masquerade', 'name': 'Masquerade IPv4', 'type': 'masquerade', 'enabled': True,
                              'source_zone': 'lan', 'destination_zone': 'wan', 'protocol': 'any'}]
            invalid = copy.deepcopy(config)
            invalid['rules'][2]['fast_path'] = True
            _, draft_headers = api('/config')
            api('/config', 'PUT', invalid, expected=422, **{'If-Match': draft_headers['ETag']})
            revision = save(config)
            plan = api('/changes/plan', 'POST', config)[0]
            assert 'flow add @transit' in plan['flow_nftables'] and 'anti-lockout' in plan['nftables']
            assert apply('flow-lab-first', revision)['status'] == 'pending'
            assert flow()['active'], flow()
            api('/changes/flow-lab-first/confirm', 'POST', {})
            lan_access()

            live = udp_client(WAN, UDP)
            assert live('ordinary', 12) == 12
            ipv6 = udp_client(WAN6, UDP)
            assert ipv6('ipv6', 8) == 8
            tcp = f"""import socket
with socket.create_connection(('{WAN}',{TCP}),3) as s:
 for _ in range(20):
  s.sendall(b'payload')
  assert s.recv(7)==b'payload'
"""
            run('ip', 'netns', 'exec', 'client', 'python3', '-c', tcp)
            counters = flow()['counters']
            assert counters['tcp'] > 0 and counters['udp'] >= 2, counters
            assert counters['ingress_packets'] >= 12 and counters['ingress_bytes'] > 0, counters
            logged = udp_client(WAN, LOGGED)
            before = flow()['counters']
            assert logged('logged', 8) == 8
            after = flow()['counters']
            assert after['udp'] == before['udp'] and after['ingress_packets'] == before['ingress_packets'], (before, after)
            assert 'gfw:' + str(revision) + ':forward:accept:mandatory-udp' in run('nft', 'list', 'table', 'inet', 'gfw')
            print('PASS: real TCP/UDP fast path and counters with IPv4 NAT and IPv6, mandatory NFLOG stays on normal path, LAN anti-lockout', flush=True)

            inspected = udp_client(IPS, UDP)
            assert inspected('ordinary', 6) == 6
            ids = {'enabled': True, 'mode': 'ips', 'failure_policy': 'closed',
                   'interfaces': ['ips0'], 'home_net': ['203.0.113.0/24'],
                   'rules': 'drop udp any any -> any 48102 (msg:"flow lab"; content:"ips-block"; sid:1000200; rev:1;)'}
            _, headers = api('/ids/config')
            ids_rev = api('/ids/config', 'PUT', ids, **{'If-Match': headers['ETag']})[0]['revision']
            assert api('/ids/apply', 'POST', {'id': 'flow-lab-ips', 'revision': ids_rev, 'timeout_seconds': 60})[0]['status'] == 'pending'
            assert not flow()['active'] and inspected('ips-block', 1) == 0
            api('/ids/changes/flow-lab-ips/confirm', 'POST', {})
            wait(lambda: flow()['active'])
            assert flow()['interfaces'] == ['lan0', 'wan0'] and flow()['excluded'][0]['interface'] == 'ips0', flow()
            before = flow()['counters']
            assert inspected('ordinary', 5) == 5 and inspected('ips-block', 1) == 0
            assert flow()['counters']['udp'] == before['udp'], flow()
            assert live('ordinary', 8) == 8 and flow()['counters']['udp'] > 0
            print('PASS: existing IPS flow evicted before IPS activation, unaffected WAN remains accelerated', flush=True)

            changed = copy.deepcopy(config)
            changed['rules'][1].update(action='drop', fast_path=False)
            assert apply('flow-lab-timeout', save(changed))['status'] == 'pending'
            assert live('ordinary', 1) == 0
            lan_access()
            wait(lambda: not api('/changes/state')[0].get('pending'), 40)
            wait(lambda: flow()['active'])
            assert live('ordinary', 10) == 10
            api('/changes/flow-lab-timeout/confirm', 'POST', {}, expected=409)
            print('PASS: changing policy invalidates live flow immediately and real 30-second rollback restores it', flush=True)

            assert apply('flow-lab-crash', save(changed))['status'] == 'pending'
            agent.kill()
            agent.wait(timeout=5)
            agent = launch_agent()
            wait(lambda: flow()['active'])
            assert live('ordinary', 8) == 8
            lan_access()
            print('PASS: agent restart clears staged flowtable and restores confirmed policy', flush=True)
        except Exception:
            print(log.read_text(), flush=True)
            raise
        finally:
            for proc in reversed(procs):
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=15)


if __name__ == '__main__':
    main()
