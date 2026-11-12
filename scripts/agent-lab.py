#!/usr/bin/env python3
"""Disposable, isolated Linux network namespaces only. Run via test-alt-p10.sh."""
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

ROOT = Path('/state')
ROOT.mkdir(mode=0o700, exist_ok=True)
SOCKET = str(ROOT / 'agent.sock')
ARCH = {'aarch64': 'arm64', 'x86_64': 'amd64'}[os.uname().machine]
BINARY = '/work/bin/linux-' + ARCH + '/gfw-agent'
CMD = [BINARY, '-enable-apply', '-socket', SOCKET, '-state-dir', str(ROOT / 'recovery'),
       '-lan-interface', 'lan0', '-management-port', '8443', '-nft', '/usr/sbin/nft']


def sh(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs).stdout


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(SOCKET)


def api(method, path, data=None, expected=200):
    c = UnixHTTP('agent', timeout=90)
    try:
        c.request(method, '/v1/firewall' + path, None if data is None else json.dumps(data), {'Content-Type': 'application/json'})
        r = c.getresponse()
        body = r.read().decode()
        assert r.status == expected, (method, path, r.status, body)
        return json.loads(body)
    finally:
        c.close()


def start():
    log = open(ROOT / 'agent.log', 'a')
    p = subprocess.Popen(CMD, stdout=log, stderr=log)
    log.close()
    for _ in range(200):
        if p.poll() is not None:
            raise AssertionError((p.returncode, (ROOT / 'agent.log').read_text()))
        try:
            api('GET', '')
            return p
        except (OSError, http.client.HTTPException):
            time.sleep(0.05)
    raise AssertionError('agent startup timeout')


def table():
    return sh('nft', '-s', '-n', 'list', 'table', 'inet', 'gfw')


def state_change(p, signal_number):
    p.send_signal(signal_number)
    p.wait(timeout=30)


def change(id, revision, config):
    return {'id': id, 'revision': revision, 'timeout_seconds': 30, 'config': config}


def peer(prefix, addr, address6):
    namespace = 'gfw-' + prefix
    sh('ip', 'netns', 'add', namespace)
    sh('ip', 'link', 'add', prefix + '0', 'type', 'veth', 'peer', 'name', prefix + '-client')
    sh('ip', 'link', 'set', prefix + '-client', 'netns', namespace)
    sh('ip', 'addr', 'add', addr + '.1/24', 'dev', prefix + '0')
    sh('ip', '-6', 'addr', 'add', address6 + '::1/64', 'dev', prefix + '0', 'nodad')
    sh('ip', 'link', 'set', prefix + '0', 'up')
    sh('ip', '-n', namespace, 'addr', 'add', addr + '.2/24', 'dev', prefix + '-client')
    sh('ip', '-n', namespace, '-6', 'addr', 'add', address6 + '::2/64', 'dev', prefix + '-client', 'nodad')
    sh('ip', '-n', namespace, 'link', 'set', prefix + '-client', 'up')
    sh('ip', '-n', namespace, 'link', 'set', 'lo', 'up')


def probe(namespace, url, succeeds):
    r = subprocess.run(['ip', 'netns', 'exec', namespace, 'curl', '-g', '--noproxy', '*', '--max-time', '2', '-fsS', url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert (r.returncode == 0) == succeeds, (namespace, url, r.returncode, r.stderr.decode())


sh('ip', 'link', 'set', 'lo', 'up')
peer('lan', '192.0.2', '2001:db8:1')
peer('wan', '198.51.100', '2001:db8:2')
sh('nft', 'add', 'table', 'inet', 'external_test')
sh('nft', 'add', 'table', 'inet', 'gfw')
bad = subprocess.run(CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
assert bad.returncode != 0 and 'ownership' in bad.stderr.decode(), bad.stderr
sh('nft', 'list', 'table', 'inet', 'gfw')
sh('nft', 'delete', 'table', 'inet', 'gfw')
print('PASS: foreign table ownership is protected', flush=True)

httpd = subprocess.Popen(['python3', '-m', 'http.server', '8443', '--bind', '0.0.0.0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
httpd6 = subprocess.Popen(['python3', '-m', 'http.server', '8444', '--bind', '::'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
# Separate IPv6 listener on the same protected port uses IPV6_V6ONLY.
code6 = "import socket,http.server; s=socket.socket(socket.AF_INET6); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('::',8443)); s.listen();\nwhile True:\n c,a=s.accept(); c.recv(8192); c.sendall(b'HTTP/1.0 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK'); c.close()"
httpd6.terminate(); httpd6.wait()
httpd6 = subprocess.Popen(['python3', '-c', code6], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
p = None
try:
    p = start()
    c = {'default_input': 'drop', 'default_forward': 'drop', 'rules': [
        {'id': 'deny-input', 'name': 'Deny all input', 'chain': 'input', 'family': 'any', 'source': '', 'destination': '', 'protocol': 'any', 'destination_port': 0, 'action': 'drop', 'enabled': True},
        {'id': 'deny-output', 'name': 'Deny all output', 'chain': 'output', 'family': 'any', 'source': '', 'destination': '', 'protocol': 'any', 'destination_port': 0, 'action': 'drop', 'enabled': True}]}
    plan = api('POST', '/plan', c)
    assert plan['kernel_validated'] and plan['safety']['lan_interface'] == 'lan0'
    first = change('lab-first', 1, c)
    assert api('POST', '/apply', first)['status'] == 'pending'
    before = table()
    assert before.index('gfw:anti-lockout') < before.index('gfw:deny-input')
    assert api('POST', '/apply', first)['id'] == 'lab-first'
    assert table() == before
    api('POST', '/apply', change('lab-overlap', 2, c), expected=409)
    probe('gfw-lan', 'http://192.0.2.1:8443', True)
    probe('gfw-lan', 'http://[2001:db8:1::1]:8443', True)
    probe('gfw-wan', 'http://198.51.100.1:8443', False)
    probe('gfw-wan', 'http://[2001:db8:2::1]:8443', False)
    print('PASS: real nft check/apply; LAN IPv4/IPv6 access survives input AND output deny; WAN blocked', flush=True)
    api('POST', '/lab-first/rollback')
    assert not json.loads(sh('nft', '-j', 'list', 'tables'))['nftables'] == []  # foreign table remains
    assert 'gfw' not in [x.get('table', {}).get('name') for x in json.loads(sh('nft', '-j', 'list', 'tables'))['nftables']]
    print('PASS: first-install rollback removes only GFW table', flush=True)

    api('POST', '/apply', change('lab-confirmed', 2, c))
    api('POST', '/lab-confirmed/confirm')
    baseline = table()
    next_config = json.loads(json.dumps(c)); next_config['rules'][0]['id'] = 'deny-next'
    api('POST', '/apply', change('lab-crash', 3, next_config))
    state_change(p, signal.SIGKILL); p = start()
    assert table() == baseline
    assert 'pending' not in api('GET', '')
    print('PASS: SIGKILL + restart immediately rolls back unconfirmed rules; stale socket recovered', flush=True)
    state_change(p, signal.SIGTERM); p = None
    sh('nft', 'delete', 'table', 'inet', 'gfw')
    p = start()
    assert table() == baseline
    print('PASS: confirmed rules restored after empty-kernel simulation', flush=True)

    api('POST', '/apply', change('lab-timeout', 4, next_config))
    print('Waiting for real 30-second confirmation timeout…', flush=True)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        s = api('GET', '')
        if 'pending' not in s:
            break
        time.sleep(.25)
    assert 'pending' not in api('GET', '') and table() == baseline
    api('POST', '/lab-timeout/confirm', expected=409)
    assert api('GET', '')['history'][-1]['status'] == 'rolled_back'
    sh('nft', 'list', 'table', 'inet', 'external_test')
    print('PASS: real timer rollback; late confirmation rejected; foreign table intact', flush=True)

    api('POST', '/apply', change('lab-shutdown', 5, next_config))
    state_change(p, signal.SIGTERM); p = None
    assert table() == baseline
    print('PASS: graceful shutdown rolls back', flush=True)
    print('VERSIONS:', sh('nft', '--version').strip(), sh('uname', '-r').strip(), flush=True)
finally:
    if p is not None and p.poll() is None:
        p.terminate(); p.wait(timeout=30)
    httpd.terminate(); httpd.wait(timeout=5)
    httpd6.terminate(); httpd6.wait(timeout=5)
