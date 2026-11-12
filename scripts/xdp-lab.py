#!/usr/bin/env python3
"""Verify WAN XDP policy and confirmation with real packets in an isolated ALT namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:8088'
STATE = Path('/state')
WAN = '192.0.2.1'
WAN6 = '2001:db8:1::1'
LAN = '198.51.100.1'
PORT = 40100


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout


def wait(check, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, urllib.error.HTTPError):
            pass
        time.sleep(0.15)
    raise AssertionError('Timed out: ' + check.__name__)


def fixture_port(name, peer, ip, addresses):
    run('ip', 'netns', 'add', peer)
    run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', peer)
    run('ip', 'addr', 'add', ip + '/24', 'dev', name)
    run('ip', 'link', 'set', name, 'up')
    for address in addresses:
        run('ip', '-n', peer, 'addr', 'add', address + '/24', 'dev', 'peer0')
    run('ip', '-n', peer, 'link', 'set', 'peer0', 'up')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('generic', 'native'), default='generic')
    parser.add_argument('--unit-capabilities', action='store_true')
    options = parser.parse_args()
    run('rpm', '-Uvh', f'/work/dist/gfw-0.22.5-1.altp10.{os.uname().machine}.rpm')
    run('ip', 'link', 'set', 'lo', 'up')
    fixture_port('lan0', 'local', LAN, ['198.51.100.2'])
    fixture_port('wan0', 'external', WAN, ['192.0.2.' + str(i) for i in range(2, 6)])
    run('ip', 'link', 'add', 'link', 'lan0', 'name', 'lan0.7', 'type', 'vlan', 'id', '7')
    run('ip', 'link', 'set', 'lan0.7', 'up')
    run('ip', '-6', 'addr', 'add', WAN6 + '/64', 'dev', 'wan0', 'nodad')
    run('ip', '-n', 'external', '-6', 'addr', 'add', '2001:db8:1::3/64', 'dev', 'peer0', 'nodad')
    wan_mac = json.loads(run('ip', '-j', 'link', 'show', 'wan0'))[0]['address']
    run('ip', '-n', 'external', '-6', 'neigh', 'replace', WAN6, 'lladdr', wan_mac, 'nud', 'permanent', 'dev', 'peer0')

    agent_log, panel_log = STATE / 'xdp-agent.log', STATE / 'xdp-panel.log'
    with agent_log.open('w') as agent_output, panel_log.open('w') as panel_output:
        def launch_agent():
            command = []
            if options.unit_capabilities:
                command = ['setpriv', '--no-new-privs',
                           '--bounding-set=-all,+net_admin,+chown,+net_bind_service,+net_raw,+setuid,+setgid,+kill,+sys_chroot,+bpf,+perfmon']
            return subprocess.Popen(command + ['/usr/sbin/gfw-agent', '-enable-apply', '-enable-xdp', '-enable-network',
                                     '-lan-interface', 'lan0', '-management-port', '8443',
                                     '-socket', str(STATE / 'agent.sock'), '-state-dir', '/var/lib/gfw-agent'],
                                    stdout=agent_output, stderr=agent_output)

        agent = launch_agent()
        panel = subprocess.Popen(['/usr/sbin/gfwd', '-listen', '127.0.0.1:8088', '-data-dir', '/var/lib/gfw',
                                  '-agent-socket', str(STATE / 'agent.sock')], stdout=panel_output, stderr=panel_output)
        try:
            wait(lambda: urllib.request.urlopen(BASE + '/healthz', timeout=1).status == 200)
            token = Path('/var/lib/gfw/admin.token').read_text().strip()

            def api(path, method='GET', body=None, expected=200, **headers):
                headers.update({'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                req = urllib.request.Request(BASE + '/api/v1' + path, headers=headers,
                                             method=method, data=None if body is None else json.dumps(body).encode())
                try:
                    with urllib.request.urlopen(req, timeout=8) as response:
                        assert response.status == expected
                        return json.load(response), response.headers
                except urllib.error.HTTPError as error:
                    result = json.load(error)
                    if error.code == 503 and expected == 200 and path == '/xdp/state':
                        raise error
                    assert error.code == expected, (path, error.code, result)
                    return result, error.headers

            def state():
                return api('/xdp/state')[0]

            def change(id, revision, profile, expected=200):
                return api('/xdp/apply', 'POST', {'id': id, 'revision': revision, 'profile': profile,
                                                 'timeout_seconds': 30}, expected)[0]

            def seed_feed(values):
                body = ('\n'.join(values) + '\n').encode()
                digest = hashlib.sha256(body).hexdigest()
                with sqlite3.connect('/var/lib/gfw/gfw.db') as db:
                    db.execute('INSERT OR REPLACE INTO feed_snapshot VALUES(?,?,?,?,?,?)',
                               ('ips.txt', len(values), digest, 'fixture', body, body))
                return digest

            wait(lambda: state()['enabled'])
            digest = seed_feed(['192.0.2.3/32', '192.0.2.4/32', '2001:db8:1::3/128'])
            draft, headers = api('/config')
            config = draft['config']
            for zone in config['zones']:
                if zone['kind'] == 'lan':
                    zone['interfaces'] = ['lan0']
                elif zone['kind'] == 'wan':
                    zone['interfaces'] = ['wan0', 'lan0.7']
            config['rules'] = [
                {'id': 'xdp-lab-udp', 'name': 'Permit UDP', 'chain': 'input', 'family': 'any', 'protocol': 'udp',
                 'destination_port': PORT, 'action': 'accept', 'enabled': True},
            ]
            revision = api('/config', 'PUT', config, **{'If-Match': headers['ETag']})[0]['revision']
            api('/changes/apply', 'POST', {'id': 'xdp-base-firewall', 'revision': revision, 'timeout_seconds': 60})
            api('/changes/xdp-base-firewall/confirm', 'POST', {})

            profile = {'interfaces': ['wan0'], 'mode': options.mode, 'match': 'source',
                       'block': ['192.0.2.2'], 'feed_sha256': digest, 'exceptions': ['192.0.2.4']}
            assert 'LAN' in change('a' * 32, 0, {**profile, 'interfaces': ['lan0']}, 422)['error']
            assert 'LAN' in change('b' * 32, 0, {**profile, 'interfaces': ['lan0.7']}, 422)['error']
            assert state()['available_feed']['sha256'] == digest
            assert change('c' * 32, 0, profile)['status'] == 'pending'
            assert change('c' * 32, 0, profile)['status'] == 'pending'

            def datagram(source, allowed):
                ipv6 = ':' in source
                destination = WAN6 if ipv6 else WAN
                family = socket.AF_INET6 if ipv6 else socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as sink:
                    sink.bind((destination, PORT))
                    sink.settimeout(0.5 if not allowed else 2)
                    run('ip', 'netns', 'exec', 'external', 'python3', '-c',
                        f"import socket; s=socket.socket({int(family)},socket.SOCK_DGRAM); "
                        f"s.bind(('{source}',0)); s.sendto(b'xdp-fixture',('{destination}',{PORT}))")
                    try:
                        packet, _ = sink.recvfrom(64)
                    except socket.timeout:
                        assert not allowed, source
                    else:
                        assert allowed and packet == b'xdp-fixture', source

            def check_lan():
                with socket.socket() as listener:
                    listener.bind((LAN, 8443))
                    listener.listen()
                    run('ip', 'netns', 'exec', 'local', 'python3', '-c',
                        f"import socket; socket.create_connection(('{LAN}',8443),2).close()")

            datagram('192.0.2.2', False)
            datagram('192.0.2.3', False)
            datagram('2001:db8:1::3', False)
            datagram('192.0.2.4', True)
            datagram('192.0.2.5', True)
            check_lan()
            runtime = state()['runtime'][0]
            assert runtime['name'] == 'wan0' and runtime['manual_drops'] == 1 and runtime['feed_drops'] == 2, runtime
            assert runtime['manual_bytes'] > 0 and runtime['feed_bytes'] > 0 and runtime['passed'] >= 2, runtime
            assert api('/xdp/changes/' + 'c' * 32 + '/confirm', 'POST', {})[0]['status'] == 'confirmed'
            assert state()['confirmed']['feed']['sha256'] == digest
            print('PASS: XDP filters IPv4/IPv6 before input, counts manual/feed drops, honors exceptions and protects LAN topology', flush=True)

            assert change('d' * 32, 1, {'interfaces': []})['status'] == 'pending'
            datagram('192.0.2.2', True)
            wait(lambda: not state().get('pending'), 40)
            current = state()
            assert current['history'][-1]['status'] == 'rolled_back' and current['revision'] == 1, current
            datagram('192.0.2.2', False)
            api('/xdp/changes/' + 'd' * 32 + '/confirm', 'POST', {}, expected=409)
            print('PASS: real 30-second automatic rollback restores XDP and rejects late confirmation', flush=True)

            seed_feed(['203.0.113.8/32'])
            assert state()['available_feed']['sha256'] != digest
            staged = {**profile, 'match': 'destination', 'block': [WAN]}
            assert change('e' * 32, 1, staged)['status'] == 'pending'
            datagram('192.0.2.5', False)
            agent.kill()
            agent.wait(timeout=5)
            agent = launch_agent()
            wait(lambda: state()['enabled'])
            current = state()
            assert current['revision'] == 1 and current['history'][-1]['status'] == 'rolled_back', current
            assert current['confirmed']['feed']['sha256'] == digest
            datagram('192.0.2.5', True)
            datagram('192.0.2.3', False)
            check_lan()
            audit, _ = api('/audit')
            assert any(entry['action'] == 'xdp.confirm.request:' + 'c' * 32 for entry in audit)
            print('PASS: a new subscription snapshot requires approval and SIGKILL restores the confirmed revision', flush=True)

            network, _ = api('/network/config')
            net_apply, _ = api('/network/apply', 'POST', {'id': 'xdp-network-change', 'revision': network['revision'],
                                                         'timeout_seconds': 30})
            assert net_apply['status'] == 'pending' and not state()['runtime']
            datagram('192.0.2.2', True)
            check_lan()
            api('/network/changes/xdp-network-change/confirm', 'POST', {})
            wait(lambda: state()['runtime'])
            datagram('192.0.2.2', False)
            check_lan()
            print('PASS: network transaction suspends XDP and safely restores it after confirmation', flush=True)
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
