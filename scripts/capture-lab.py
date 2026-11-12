#!/usr/bin/env python3
"""Exercise GFW capture with real traffic in an isolated Linux namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path('/state')
BASE = 'http://127.0.0.1:8088'
PEER = '192.0.2.2'
GATEWAY = '192.0.2.1'


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout


def wait(test, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = test()
            if result:
                return result
        except (OSError, urllib.error.HTTPError):
            pass
        time.sleep(0.1)
    raise AssertionError('timed out: ' + test.__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--unit-capabilities', action='store_true')
    options = parser.parse_args()
    run('rpm', '-Uvh', f'/work/dist/gfw-0.22.2-1.altp10.{os.uname().machine}.rpm')
    run('ip', 'netns', 'add', 'capture-peer')
    run('ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', 'capture-peer')
    run('ip', 'addr', 'add', GATEWAY + '/24', 'dev', 'lan0')
    run('ip', 'link', 'set', 'lan0', 'up')
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', '-n', 'capture-peer', 'addr', 'add', PEER + '/24', 'dev', 'peer0')
    run('ip', '-n', 'capture-peer', 'link', 'set', 'peer0', 'up')

    agent_log = ROOT / 'agent.log'
    panel_log = ROOT / 'panel.log'
    with agent_log.open('w') as a_log, panel_log.open('w') as p_log:
        def start_agent():
            command = []
            if options.unit_capabilities:
                command = ['setpriv', '--no-new-privs',
                           '--bounding-set=-all,+net_admin,+chown,+net_bind_service,+net_raw,+setuid,+setgid,+kill,+sys_chroot,+bpf,+perfmon']
            return subprocess.Popen(command + ['/usr/sbin/gfw-agent', '-enable-apply', '-enable-capture',
                                     '-lan-interface', 'lan0', '-management-port', '8443',
                                     '-socket', str(ROOT / 'agent.sock'), '-state-dir', '/var/lib/gfw-agent'],
                                    stdout=a_log, stderr=a_log)

        agent = start_agent()
        panel = subprocess.Popen(['/usr/sbin/gfwd', '-listen', '127.0.0.1:8088', '-data-dir', '/var/lib/gfw',
                                  '-agent-socket', str(ROOT / 'agent.sock')], stdout=p_log, stderr=p_log)
        try:
            wait(lambda: urllib.request.urlopen(BASE + '/healthz', timeout=1).status == 200)
            key = Path('/var/lib/gfw/admin.token').read_text().strip()

            def request(path, method='GET', body=None, authenticated=True, **headers):
                if authenticated:
                    headers['Authorization'] = 'Bearer ' + key
                if body is not None:
                    headers['Content-Type'] = 'application/json'
                req = urllib.request.Request(BASE + '/api/v1' + path, headers=headers,
                                             method=method, data=None if body is None else json.dumps(body).encode())
                try:
                    return urllib.request.urlopen(req, timeout=8)
                except urllib.error.HTTPError as error:
                    raise AssertionError((error.code, error.read().decode())) from error

            def api(path, method='GET', body=None, **headers):
                with request(path, method, body, **headers) as response:
                    return json.load(response), response.headers

            def enabled():
                try:
                    return api('/captures')[0]['enabled']
                except AssertionError as error:
                    if isinstance(error.args[0], tuple) and error.args[0][0] == 503:
                        return False
                    raise

            wait(enabled)
            draft, headers = api('/config')
            draft['config']['rules'] = [
                {'id': 'udp-capture-lab', 'name': 'Lab UDP', 'chain': 'input', 'family': 'ipv4',
                 'protocol': 'udp', 'destination_port': 40001, 'action': 'accept', 'enabled': True},
            ]
            revision = api('/config', 'PUT', draft['config'], **{'If-Match': headers['ETag']})[0]['revision']
            api('/changes/apply', 'POST', {'id': 'capture-lab', 'revision': revision, 'timeout_seconds': 60})
            api('/changes/capture-lab/confirm', 'POST', {})

            config = {'interface': 'lan0', 'direction': 'in', 'family': 'ip', 'protocol': 'udp',
                      'source': '192.0.2.0/24', 'destination': GATEWAY, 'source_ports': '41000-41002',
                      'destination_ports': '40001', 'seconds': 15, 'max_packets': 1, 'max_mib': 4,
                      'retention_hours': 1}
            payload = b'gfw-capture-lab-' * 50

            def send_packets():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                    receiver.bind((GATEWAY, 40001))
                    receiver.settimeout(3)
                    run('ip', 'netns', 'exec', 'capture-peer', 'python3', '-c',
                        f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('{PEER}',41000)); "
                        f"s.sendto(b'excluded',('{GATEWAY}',40002)); s.sendto({payload!r},('{GATEWAY}',40001))")
                    assert receiver.recv(1600) == payload

            def completed(id):
                for entry in api('/captures')[0]['sessions']:
                    if entry['id'] == id and entry['state'] != 'running':
                        return entry
                return None

            def capture(backend):
                session, _ = api('/captures', 'POST', {**config, 'backend': backend})
                assert session['backend'] == backend, session
                time.sleep(0.3)
                send_packets()
                done = wait(lambda: completed(session['id']))
                assert done['state'] == 'complete' and done['reason'] == 'packets', done
                assert done['packets'] == 1 and done['truncated'] == 0 and done['dropped'] == 0, done
                path = '/captures/' + done['id'] + '/file'
                with request(path) as response:
                    body = response.read()
                assert hashlib.sha256(body).hexdigest() == done['sha256']
                assert payload in body and b'excluded' not in body
                assert len(body) == done['bytes']
                with request(path, Range='bytes=0-23') as response:
                    assert response.status == 206 and response.read() == body[:24]
                try:
                    request(path, authenticated=False)
                    raise AssertionError('PCAP exposed without authentication')
                except AssertionError as error:
                    assert error.args[0][0] == 401, error
                output = ROOT / 'test.pcap'
                output.write_bytes(body)
                assert '.40001:' in run('tcpdump', '-nn', '-r', str(output))
                caplen, original = struct.unpack_from('<II', body, 32)
                assert caplen == original == len(payload) + 42
                return done

            af_packet = capture('packet')
            xdp = capture('xdp-generic')
            if options.native:
                capture('xdp')
            assert 'prog/xdp' not in run('ip', '-details', 'link', 'show', 'lan0')
            egress, _ = api('/captures', 'POST', {**config, 'backend': 'auto', 'direction': 'out',
                                                 'source': GATEWAY, 'destination': PEER})
            assert egress['backend'] == 'packet'
            time.sleep(0.3)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.bind((GATEWAY, 41000))
                sender.sendto(payload, (PEER, 40001))
            done = wait(lambda: completed(egress['id']))
            assert done['state'] == 'complete' and done['packets'] == 1, done
            with socket.socket() as lan:
                lan.bind((GATEWAY, 8443))
                lan.listen()
                run('ip', 'netns', 'exec', 'capture-peer', 'python3', '-c',
                    f"import socket; socket.create_connection(('{GATEWAY}',8443),2).close()")
            modes = 'AF_PACKET, generic XDP and native XDP' if options.native else 'AF_PACKET and generic XDP'
            print(f'PASS: {modes} filter real packets, retain payload, detach XDP and preserve LAN access', flush=True)

            timed, _ = api('/captures', 'POST', {**config, 'backend': 'packet', 'seconds': 1, 'max_packets': 0})
            done = wait(lambda: completed(timed['id']))
            assert done['state'] == 'complete' and done['reason'] == 'duration' and done['packets'] == 0, done

            manual, _ = api('/captures', 'POST', {**config, 'backend': 'packet', 'max_packets': 0, 'snaplen': 64})
            time.sleep(0.3)
            send_packets()
            wait(lambda: next(s for s in api('/captures')[0]['sessions'] if s['id'] == manual['id'])['packets'] == 1)
            api('/captures/' + manual['id'] + '/stop', 'POST')
            done = wait(lambda: completed(manual['id']))
            assert done['state'] == 'complete' and done['reason'] == 'manual' and done['truncated'] == 1, done

            session, _ = api('/captures', 'POST', {**config, 'backend': 'packet', 'max_packets': 0})
            time.sleep(0.3)
            send_packets()
            wait(lambda: next(s for s in api('/captures')[0]['sessions'] if s['id'] == session['id'])['packets'] == 1)
            agent.kill()
            agent.wait(timeout=5)
            agent = start_agent()
            wait(enabled)
            recovered = wait(lambda: completed(session['id']))
            assert recovered['state'] == 'incomplete' and recovered['reason'] == 'restart' and recovered['packets'] == 1, recovered
            assert recovered['sha256']
            api('/captures/' + af_packet['id'], 'DELETE')
            history, _ = api('/audit')
            assert any(e['action'] == 'capture.download.request:' + xdp['id'] for e in history)
            assert any(e['action'] == 'capture.delete.request:' + af_packet['id'] for e in history)
            print('PASS: access control, ranged PCAP download, audits and recovery after SIGKILL', flush=True)
        except Exception:
            print(agent_log.read_text(), panel_log.read_text(), sep='\n', flush=True)
            raise
        finally:
            for proc in (panel, agent):
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=15)


if __name__ == '__main__':
    main()
