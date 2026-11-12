#!/usr/bin/env python3
"""Run after firewall tests in the same disposable, network-none ALT container."""
import copy
import json
from pathlib import Path
import runpy
import signal
import subprocess
import time

lab = runpy.run_path('/work/scripts/agent-lab.py')
sh, api, start, stop, probe = [lab[x] for x in ('sh', 'api', 'start', 'state_change', 'probe')]
lab['CMD'].extend(['-enable-network'])


def network(method, path='', data=None, expected=200):
    c = lab['UnixHTTP']('agent', timeout=90)
    try:
        c.request(method, '/v1/network' + path, None if data is None else json.dumps(data), {'Content-Type': 'application/json'})
        r = c.getresponse()
        body = r.read().decode()
        assert r.status == expected, (path, r.status, body)
        return json.loads(body)
    finally:
        c.close()


def link(name, kind='physical', addresses=None, **kwargs):
    out = {'name': name, 'type': kind, 'parent': '', 'vlan': 0, 'members': [], 'bond_mode': '', 'mtu': 1500,
           'up': True, 'addresses': addresses or [], 'adopt': kind == 'physical'}
    out.update(kwargs)
    return out


def apply(id, revision, config):
    return network('POST', '/apply', {'id': id, 'revision': revision, 'timeout_seconds': 30, 'config': config})


for name in ('port1', 'port2'):
    sh('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', name + '-peer')
    sh('ip', 'link', 'set', name, 'up')
    sh('ip', 'link', 'set', name + '-peer', 'up')
sh('ip', 'addr', 'add', '172.30.1.1/24', 'dev', 'port1')
sh('ip', 'route', 'add', '198.19.0.0/16', 'via', '172.30.1.254', 'dev', 'port1', 'metric', '75', 'proto', 'static')
Path('/etc/net/ifaces/port1').mkdir()
Path('/etc/net/ifaces/port1/options').write_text('TYPE=eth\nBOOTPROTO=static\nONBOOT=yes\n')
Path('/etc/net/ifaces/port1/ipv4address').write_text('172.30.1.1/24\n')
before_files = {p.name: p.read_bytes() for p in Path('/etc/net/ifaces/port1').iterdir()}
before_mac = json.loads(sh('ip', '-j', 'link', 'show', 'port1'))[0]['address']
c = {'interfaces': [link('port1'), link('port2'),
                    link('bond0', 'bond', members=['port1', 'port2'], bond_mode='active-backup'),
                    link('vlan100', 'vlan', parent='bond0', vlan=100),
                    link('br100', 'bridge', ['10.100.0.1/24', '2001:db8:100::1/64'], members=['vlan100'])],
     'routes': [{'destination': '198.18.0.0/16', 'gateway': '10.100.0.254', 'interface': 'br100', 'metric': 50},
                {'destination': '2001:db8:200::/64', 'gateway': '2001:db8:100::fe', 'interface': 'br100', 'metric': 50}]}
p = start()
try:
    plan = network('POST', '/plan', c)
    assert 'lan0' in plan['protected'] and 'BONDMODE=1' in plan['files']['bond0']['options']
    assert apply('net-first', 1, c)['status'] == 'pending'
    network('POST', '/apply', {'id': 'net-first', 'revision': 1, 'timeout_seconds': 30, 'config': c})
    api('POST', '/apply', lab['change']('fw-network-overlap', 100, lab['c']), expected=409)
    assert json.loads(sh('ip', '-j', '-d', 'link', 'show', 'bond0'))[0]['linkinfo']['info_data']['mode'] == 'active-backup'
    assert '10.100.0.1/24' in sh('ip', '-4', 'addr', 'show', 'br100')
    assert '2001:db8:100::1/64' in sh('ip', '-6', 'addr', 'show', 'br100')
    assert '198.18.0.0/16' in sh('ip', 'route', 'show', 'dev', 'br100')
    assert '2001:db8:200::/64' in sh('ip', '-6', 'route', 'show', 'dev', 'br100')
    assert 'VID=100' in Path('/etc/net/ifaces/vlan100/options').read_text()
    assert 'proto 186' in Path('/etc/net/ifaces/br100/ipv4route').read_text()
    print('PASS: real bond + VLAN + bridge, IPv4/IPv6 addresses/routes, typed etcnet files, mutual exclusion', flush=True)
    api('POST', '/net-first/rollback')
    assert not Path('/etc/net/ifaces/bond0').exists()
    assert before_files == {x.name: x.read_bytes() for x in Path('/etc/net/ifaces/port1').iterdir()}
    assert '172.30.1.1/24' in sh('ip', 'addr', 'show', 'port1')
    assert '198.19.0.0/16' in sh('ip', 'route', 'show', 'dev', 'port1')
    assert json.loads(sh('ip', '-j', 'link', 'show', 'port1'))[0]['address'] == before_mac
    print('PASS: rollback restores foreign static addresses/routes, MAC, original etcnet files; new virtual links removed', flush=True)

    apply('net-confirm', 2, c)
    api('POST', '/net-confirm/confirm')
    changed = copy.deepcopy(c); changed['interfaces'][-1]['addresses'].append('10.100.0.2/24')
    apply('net-crash', 3, changed)
    stop(p, signal.SIGKILL); p = start()
    assert 'pending' not in network('GET')
    assert '10.100.0.2/24' not in sh('ip', 'addr', 'show', 'br100')
    assert '10.100.0.2/24' not in Path('/etc/net/ifaces/br100/ipv4address').read_text()
    print('PASS: crash rolls back both etcnet files and kernel state', flush=True)

    # The complete namespace plan preserves the original LAN address and adds a
    # secondary one, without reloading/rebuilding the protected interface.
    with_lan = copy.deepcopy(c)
    with_lan['interfaces'].append(link('lan0', addresses=['192.0.2.1/24', '192.0.2.10/24', '2001:db8:1::1/64']))
    apply('net-lan-secondary', 4, with_lan)
    # The firewall laboratory stopped its HTTP listeners; start one again.
    web = subprocess.Popen(['python3', '-m', 'http.server', '8443', '--bind', '0.0.0.0'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            try:
                probe('gfw-lan', 'http://192.0.2.1:8443', True); break
            except AssertionError:
                time.sleep(.1)
        probe('gfw-lan', 'http://192.0.2.10:8443', True)
    finally:
        web.terminate(); web.wait(timeout=5)
    api('POST', '/net-lan-secondary/confirm')
    unsafe = copy.deepcopy(with_lan)
    unsafe['interfaces'][-1]['up'] = False
    network('POST', '/plan', unsafe, expected=422)
    unsafe = copy.deepcopy(with_lan); unsafe['interfaces'][-1]['addresses'] = ['192.0.2.99/24']
    network('POST', '/plan', unsafe, expected=422)
    unsafe = copy.deepcopy(c)
    network('POST', '/plan', unsafe, expected=422)  # removing managed LAN
    print('PASS: anti-lockout still serves original and secondary LAN IP; disabling/deleting LAN and replacing all its IPs blocked', flush=True)

    apply('net-timeout', 5, {**with_lan, 'routes': []})
    print('Waiting for real network rollback timer…', flush=True)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline and 'pending' in network('GET'):
        time.sleep(.25)
    assert 'pending' not in network('GET')
    assert '198.18.0.0/16' in sh('ip', 'route', 'show', 'dev', 'br100')
    assert '198.18.0.0/16' in Path('/etc/net/ifaces/br100/ipv4route').read_text()
    print('PASS: timeout restores routes and files without gfwd/browser', flush=True)

    # Delete owned virtual links and let the actual etcnet scripts load the
    # generated files. Kernel modules are already available (proved above).
    stop(p, signal.SIGTERM); p = None
    sh('ip', 'link', 'del', 'br100'); sh('ip', 'link', 'del', 'vlan100'); sh('ip', 'link', 'del', 'bond0')
    Path('/etc/net/options.d/99-gfw-lab').write_text('MODPROBE=/bin/true\n')
    r = subprocess.run(['/sbin/ifup', 'br100'], text=True, capture_output=True)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert '10.100.0.1/24' in sh('ip', 'addr', 'show', 'br100')
    assert '198.18.0.0/16' in sh('ip', 'route', 'show', 'dev', 'br100')
    p = start()
    assert network('GET')['confirmed_revision'] == 4
    print('PASS: actual etcnet ifup recreates bond/VLAN/bridge, addresses and routes from generated files', flush=True)
    lacp = copy.deepcopy(with_lan)
    lacp['interfaces'][2]['bond_mode'] = '802.3ad'
    apply('net-lacp', 6, lacp)
    api('POST', '/net-lacp/confirm')
    assert json.loads(sh('ip', '-j', '-d', 'link', 'show', 'bond0'))[0]['linkinfo']['info_data']['mode'] == '802.3ad'
    assert 'BONDMODE=4' in Path('/etc/net/ifaces/bond0/options').read_text()
    invalid_parent = copy.deepcopy(lacp)
    invalid_parent['interfaces'] = [x for x in invalid_parent['interfaces'] if x['name'] != 'bond0']
    network('POST', '/plan', invalid_parent, expected=422)
    delete_virtual = {'interfaces': [x for x in lacp['interfaces'] if x['type'] == 'physical'], 'routes': []}
    apply('net-delete-virtual', 7, delete_virtual)
    assert not Path('/etc/net/ifaces/br100').exists()
    assert subprocess.run(['ip', 'link', 'show', 'br100'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    api('POST', '/net-delete-virtual/rollback')
    assert '198.18.0.0/16' in sh('ip', 'route', 'show', 'dev', 'br100')
    assert 'BONDMODE=4' in Path('/etc/net/ifaces/bond0/options').read_text()
    print('PASS: active-backup to 802.3ad; used parent deletion blocked; managed virtual deletion and full rollback work', flush=True)
    print('ETCNET:', sh('rpm', '-q', 'etcnet').strip(), flush=True)
finally:
    if p is not None and p.poll() is None:
        p.terminate(); p.wait(timeout=40)
