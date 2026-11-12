#!/usr/bin/env python3
"""Test the packaged Suricata IDS on an isolated ALT p10 veth pair."""
import copy
import hashlib
import sqlite3
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

def sh(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

rpm_arch = os.uname().machine
sh('rpm', '-Uvh', f'/work/dist/gfw-0.22.6-1.altp10.{rpm_arch}.rpm')
sh('ip', 'link', 'set', 'lo', 'up')
sh('ip', 'netns', 'add', 'gfw-ids-client')
sh('ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'peer0')
sh('ip', 'link', 'set', 'peer0', 'netns', 'gfw-ids-client')
sh('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'lan0')
sh('ip', 'link', 'set', 'lan0', 'up')
sh('ip', '-n', 'gfw-ids-client', 'addr', 'add', '192.0.2.2/24', 'dev', 'peer0')
sh('ip', '-n', 'gfw-ids-client', 'link', 'set', 'peer0', 'up')
sh('ip', 'netns', 'add', 'gfw-ips-wan')
sh('ip', 'link', 'add', 'wan0', 'type', 'veth', 'peer', 'name', 'wanpeer')
sh('ip', 'link', 'set', 'wanpeer', 'netns', 'gfw-ips-wan')
sh('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'wan0')
sh('ip', 'link', 'set', 'wan0', 'up')
sh('ip', '-n', 'gfw-ips-wan', 'addr', 'add', '198.51.100.2/24', 'dev', 'wanpeer')
sh('ip', '-n', 'gfw-ips-wan', 'link', 'set', 'wanpeer', 'up')
sh('ip', '-n', 'gfw-ids-client', 'route', 'add', 'default', 'via', '192.0.2.1')
sh('ip', '-n', 'gfw-ips-wan', 'route', 'add', 'default', 'via', '198.51.100.1')
Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
for namespace, gw_if, peer_if, prefix in [
    ('gfw-ids-client', 'lan0', 'peer0', '2001:db8:1'),
    ('gfw-ips-wan', 'wan0', 'wanpeer', '2001:db8:2'),
]:
    sh('ip','-6','addr','add',prefix+'::1/64','dev',gw_if,'nodad')
    sh('ip','-n',namespace,'-6','addr','add',prefix+'::2/64','dev',peer_if,'nodad')
    sh('ip','-n',namespace,'-6','route','add','default','via',prefix+'::1')

state = Path('/state')
agent_log = (state / 'agent.log').open('ab', buffering=0)
sock = state / 'agent.sock'

def launch_agent():
    cmd = ['/usr/sbin/gfw-agent', '-enable-apply', '-enable-ids', '-socket', str(sock),
           '-state-dir', str(state / 'agent'), '-lan-interface', 'lan0', '-management-port', '8443']
    # Mirror the package unit's no-new-privileges flag and bounding set.
    if Path('/usr/bin/setpriv').exists():
        cmd = ['/usr/bin/setpriv', '--no-new-privs',
               '--bounding-set=-all,+net_admin,+chown,+net_bind_service,+net_raw,+setuid,+setgid,+kill', *cmd]
    p = subprocess.Popen(cmd, stderr=agent_log, stdout=agent_log)
    for _ in range(200):
        assert p.poll() is None, (state / 'agent.log').read_text()
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.connect(str(sock))
            return p
        except OSError:
            time.sleep(.05)
    raise RuntimeError('agent startup timeout: ' + (state / 'agent.log').read_text())

def stop(p, force=False):
    if p is not None and p.poll() is None:
        p.send_signal(signal.SIGKILL if force else signal.SIGTERM)
        p.wait(timeout=25)

agent = controller = echo = httpd = None
try:
    agent = launch_agent()
    controller = subprocess.Popen(['/usr/sbin/gfwd', '-listen', '127.0.0.1:8088', '-data-dir',
                                   str(state / 'panel'), '-agent-socket', str(sock)], stderr=agent_log)
    base = 'http://127.0.0.1:8088'
    for _ in range(200):
        try:
            urllib.request.urlopen(base+'/healthz', timeout=1).close()
            break
        except OSError:
            assert controller.poll() is None, (state / 'agent.log').read_text()
            time.sleep(.05)
    key = (state / 'panel/admin.token').read_text().strip()

    def api(method, path, data=None, headers=None, expected=200):
        request = urllib.request.Request(base+'/api/v1'+path, method=method, headers={
            'Authorization': 'Bearer '+key, 'Content-Type': 'application/json', **(headers or {})},
            data=json.dumps(data).encode() if data is not None else None)
        try:
            response = urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            assert response.status == expected, (method, path, response.status, body)
            return json.loads(body), response.headers

    fw, headers = api('GET', '/config')
    cfg = fw['config']
    cfg['rules'] = [{'id':'test-datagram','name':'Test datagram','chain':'input','family':'ipv4',
                     'protocol':'udp','source':'192.0.2.0/24','destination':'192.0.2.1/32',
                     'destination_port':40001,'action':'accept','enabled':True},
                    {'id':'ips-transit','name':'Test transit','chain':'forward','family':'ipv4',
                     'protocol':'udp','source':'192.0.2.0/24','destination':'198.51.100.2/32',
                     'destination_port':41001,'action':'accept','enabled':True},
                    {'id':'ioc-http','name':'Test HTTP file','chain':'forward','family':'ipv4',
                     'protocol':'tcp','source':'192.0.2.0/24','destination':'198.51.100.2/32',
                     'destination_port':41003,'action':'accept','enabled':True},
                    {'id':'ips-transit-v6','name':'Test IPv6 transit','chain':'forward','family':'ipv6',
                     'protocol':'udp','source':'2001:db8:1::/64','destination':'2001:db8:2::2/128',
                     'destination_port':41001,'action':'accept','enabled':True},
                    {'id':'test-nd','name':'Test IPv6 neighbor discovery','chain':'input','family':'ipv6',
                     'protocol':'icmpv6','source':'','destination':'',
                     'destination_port':0,'action':'accept','enabled':True}]
    fw,_ = api('PUT','/config',cfg,{'If-Match':headers['ETag']})
    api('POST','/changes/apply',{'id':'ids-lab-firewall','revision':fw['revision'],'timeout_seconds':60})
    api('POST','/changes/ids-lab-firewall/confirm',{})
    tcp = socket.socket()
    tcp.bind(('192.0.2.1', 8443))
    tcp.listen(8)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('192.0.2.1', 40001))
    udp.settimeout(3)

    def lan_access():
        sh('ip','netns','exec','gfw-ids-client','python3','-c',
           "import socket; socket.create_connection(('192.0.2.1',8443),2).close()")
        conn, _ = tcp.accept()
        conn.close()

    def packet(payload):
        code = "import socket,sys; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(sys.argv[1].encode(),('192.0.2.1',40001))"
        sh('ip','netns','exec','gfw-ids-client','python3','-c',code,payload)
        assert udp.recv(1024) == payload.encode()

    def expect_alert(sid, message):
        for _ in range(100):
            events, _ = api('GET','/ids/alerts')
            for event in events:
                if event['sid'] == sid:
                    assert event['message'] == message and event['interface'] == 'lan0', event
                    assert event['src'] == '192.0.2.2' and event['dst_port'] == 40001, event
                    return event
            time.sleep(.05)
        raise AssertionError((api('GET','/ids/state'),api('GET','/ids/logs')))

    draft, _ = api('GET','/ids/config')
    assert not draft['config']['enabled']
    config = {'enabled':True,'interfaces':['lan0'],'home_net':['192.0.2.0/24'],
              'rules':'alert udp any any -> $HOME_NET 40001 (msg:"GFW IDS fixture"; content:"gfw-test"; sid:1000001; rev:1;)'}
    invalid = dict(config, rules='alert udp any any -> any any (bogus-gfw-keyword; sid:1000003;)')
    api('POST','/ids/plan',invalid,expected=422)

    def save(c):
        d, headers = api('GET','/ids/config')
        return api('PUT','/ids/config',c,{'If-Match':headers['ETag']})[0]

    def apply(c, change, timeout=60):
        saved = save(c)
        plan, _ = api('POST','/ids/plan',c)
        assert plan['checked'] and plan['can_apply'], plan
        result, _ = api('POST','/ids/apply',{'id':change,'revision':saved['revision'],'timeout_seconds':timeout})
        assert result['status']=='pending', result

    apply(config,'ids-lab-first')
    state_api,_ = api('GET','/ids/state')
    assert state_api['runtime']['running'], state_api
    pids = [p for p in Path('/proc').glob('[0-9]*') if (p/'comm').exists() and (p/'comm').read_text().strip()=='Suricata-Main']
    assert len(pids)==1, pids
    creds = (pids[0]/'status').read_text()
    uid = sh('id','-u','gfw-ids').strip()
    assert f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}' in creds, creds
    assert 'CapEff:\t0000000000002000' in creds, creds
    lan_access()
    packet('gfw-test')
    original = expect_alert(1000001,'GFW IDS fixture')
    api('POST','/ids/changes/ids-lab-first/confirm',{})
    print('PASS: real AF_PACKET on ALT, non-root CAP_NET_RAW, alert in SQLite, UDP and LAN unaffected',flush=True)

    changed = copy.deepcopy(config)
    changed['rules'] = changed['rules'].replace('GFW IDS fixture','Second fixture').replace('1000001','1000002')
    apply(changed,'ids-lab-crash')
    packet('gfw-test')
    later = expect_alert(1000002,'Second fixture')
    assert later['id'] > original['id']
    older, _ = api('GET',f"/ids/alerts?before={later['id']}")
    assert any(a['id']==original['id'] for a in older)
    stop(agent, force=True)
    agent = launch_agent()
    status,_ = api('GET','/ids/state')
    assert status['runtime']['running'] and not status.get('pending')
    packet('gfw-test')
    lan_access()
    assert expect_alert(1000001,'GFW IDS fixture')['id'] >= original['id']
    assert expect_alert(1000002,'Second fixture')['id'] == later['id']
    print('PASS: SIGKILL restores confirmed rules; paginated events persist',flush=True)

    sample=b'GFW file IOC fixture, harmless'
    other=b'GFW file IOC control'
    sha=hashlib.sha256(sample).hexdigest()
    raw=json.dumps([{'type':algo+'_hash','value':hashlib.new(algo,sample).hexdigest(),
                     'source':'fixture','threat':'Test IOC'} for algo in ('md5','sha1','sha256')]).encode()
    version=hashlib.sha256(raw).hexdigest()
    with sqlite3.connect(state/'panel/gfw.db') as db:
        db.execute("INSERT INTO feed_snapshot VALUES('iocs.json',3,?,'fixture',?,NULL)",(version,raw))
        db.execute("UPDATE feed_status SET success_at='2026-11-11T00:00:00Z' WHERE id=1")

    def scan(content):
        req=urllib.request.Request(base+'/api/v1/ids/file-ioc/scan',data=content,headers={
            'Authorization':'Bearer '+key,'Content-Type':'application/octet-stream'})
        with urllib.request.urlopen(req,timeout=5) as response:
            return json.load(response)
    result=scan(sample)
    assert result['snapshot_sha256']==version and result['hashes']['sha256']==sha
    assert {x['algorithm'] for x in result['matches']}=={'sha256','sha1','md5'}
    assert not scan(other)['matches']
    print('PASS: manual scan identifies three hash types with IOC source and rejects the control',flush=True)

    draft,_=api('GET','/ids/config')
    pinned,_=api('POST','/ids/file-ioc/stage',{'revision':draft['revision'],'snapshot_sha256':version})
    assert pinned['config']['file_ioc']['snapshot_sha256']==version
    apply(config,'ids-file-ioc')
    lan_access()
    server_code = """from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  content=b'GFW file IOC fixture, harmless' if self.path=='/match.bin' else b'GFW file IOC control'
  self.send_response(200)
  self.send_header('Content-Type','application/octet-stream')
  self.send_header('Content-Length',str(len(content)))
  self.end_headers()
  self.wfile.write(content)
s=HTTPServer(('198.51.100.2',41003),Handler)
print('ready',flush=True)
s.serve_forever()
"""
    httpd=subprocess.Popen(['ip','netns','exec','gfw-ips-wan','python3','-c',server_code],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    assert httpd.stdout.readline().strip()=='ready'
    def download(name):
        return sh('ip','netns','exec','gfw-ids-client','curl','--noproxy','*','-fsS','--max-time','3','http://198.51.100.2:41003/'+name).encode()
    assert download('other.bin')==other
    assert download('match.bin')==sample
    for _ in range(100):
        alerts,_=api('GET','/ids/alerts')
        detections=[a for a in alerts if a['sid'] in (3980001,3980002,3980003)]
        if len(detections)>=3:
            break
        time.sleep(.05)
    assert {a['sid'] for a in detections}=={3980001,3980002,3980003}, (alerts,api('GET','/ids/logs'))
    assert all(version in a['message'] and a['action']=='allowed' for a in detections)
    api('POST','/ids/changes/ids-file-ioc/rollback',{})
    assert not api('GET','/ids/state')[0]['runtime'].get('file_ioc_snapshot')
    draft,_=api('GET','/ids/config')
    api('POST','/ids/file-ioc/stage',{'revision':draft['revision'],'snapshot_sha256':''})
    print('PASS: real HTTP file matches all three Suricata hashes, carries snapshot, and rolls back',flush=True)

    def suricata_pid():
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                if (proc/'comm').read_text().strip()=='Suricata-Main' and f'PPid:\t{agent.pid}\n' in (proc/'status').read_text():
                    return int(proc.name)
            except FileNotFoundError:
                continue
        raise AssertionError('Suricata is absent')

    echo_code = """import selectors,socket
sel=selectors.DefaultSelector()
for family, address, port in [(socket.AF_INET,'198.51.100.2',41001),
                               (socket.AF_INET,'198.51.100.2',41002),
                               (socket.AF_INET6,'2001:db8:2::2',41001)]:
 s=socket.socket(family,socket.SOCK_DGRAM)
 s.bind((address,port))
 sel.register(s,selectors.EVENT_READ)
print('ready',flush=True)
while True:
 for key,_ in sel.select():
  s=key.fileobj
  payload, peer=s.recvfrom(1024)
  if payload==b'flood': continue
  s.sendto(b'bad-reply' if payload==b'request-bad-reply' else b'echo:'+payload,peer)
"""
    echo=subprocess.Popen(['ip','netns','exec','gfw-ips-wan','python3','-c',echo_code],stdout=subprocess.PIPE,text=True)
    assert echo.stdout.readline().strip()=='ready'
    transit_code = """import socket,sys
payload,host,port=sys.argv[1:]
s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(payload.encode(),(host,int(port)))
try:
 print(s.recv(1024).decode())
except socket.timeout:
 print('blocked')
"""
    def transit(payload, ipv6=False, port=41001):
        host='2001:db8:2::2' if ipv6 else '198.51.100.2'
        return sh('ip','netns','exec','gfw-ids-client','python3','-c',transit_code,payload,host,str(port)).strip()

    def ips_alert(sid):
        for _ in range(100):
            alerts,_ = api('GET','/ids/alerts')
            for alert in alerts:
                if alert['sid']==sid and alert['action']=='blocked' and ':' not in alert['src']:
                    return alert
            time.sleep(.05)
        raise AssertionError(api('GET','/ids/alerts')[0])

    ips = dict(config, mode='ips', failure_policy='closed', home_net=['192.0.2.0/24','2001:db8:1::/64'], rules=(
        'drop udp $HOME_NET any -> any 41001 (msg:"Block request"; content:"bad-request"; sid:1000011; rev:1;)\n'
        'drop udp any 41001 -> $HOME_NET any (msg:"Block reply"; content:"bad-reply"; sid:1000012; rev:1;)'))
    assert transit('hello')=='echo:hello'
    draft,_=api('GET','/ids/config')
    api('POST','/ids/file-ioc/stage',{'revision':draft['revision'],'snapshot_sha256':version})
    apply(ips,'ips-lab-closed')
    status,_=api('GET','/ids/state')
    assert status['runtime']['mode']=='ips' and status['ips_hooked'] and status['runtime']['queue'], status
    assert transit('hello')=='echo:hello'
    assert transit('bad-request')=='blocked'
    assert transit('request-bad-reply')=='blocked'
    assert transit('hello',ipv6=True)=='echo:hello'
    assert transit('bad-request',ipv6=True)=='blocked'
    assert ips_alert(1000011)['src']=='192.0.2.2'
    assert ips_alert(1000012)['src']=='198.51.100.2'
    last_file_id=max(a['id'] for a in detections)
    assert download('match.bin')==sample
    for _ in range(100):
        alerts,_=api('GET','/ids/alerts')
        if any(a['sid']==3980003 and a['id']>last_file_id and a['action']=='allowed' for a in alerts):
            break
        time.sleep(.05)
    else:
        raise AssertionError('IPS did not report the transferred file hash')
    lan_access()
    api('POST','/ids/changes/ips-lab-closed/confirm',{})
    print('PASS: NFQUEUE inspects IPv4/IPv6, drops requests and stateful replies, logs verdicts, and preserves LAN',flush=True)

    def overflow(expected):
        pid=suricata_pid()
        os.kill(pid,signal.SIGSTOP)
        try:
            flood="""import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(12000):
 s.sendto(b'flood',('198.51.100.2',41001))
"""
            sh('ip','netns','exec','gfw-ids-client','python3','-c',flood)
            status,_=api('GET','/ids/state')
            q=status['runtime']['queue']
            assert q['waiting'] > 0, q
            if expected=='blocked':
                assert q['kernel_dropped']+q['user_dropped'] > 0, q
            observed=transit('overflow-probe')
            assert observed==expected, (observed, expected, status)
        finally:
            os.kill(pid,signal.SIGCONT)

    overflow('blocked')
    os.kill(suricata_pid(), signal.SIGKILL)
    assert transit('hello')=='blocked'
    lan_access()
    assert 'блокируется' in api('GET','/ids/state')[0]['ips_error']
    print('PASS: fail-closed with full queue and absent listener; LAN remains reachable',flush=True)

    opened=dict(ips, failure_policy='open')
    apply(opened,'ips-lab-open')
    assert transit('bad-request')=='blocked'
    overflow('echo:overflow-probe')
    os.kill(suricata_pid(), signal.SIGKILL)
    assert transit('hello')=='echo:hello'
    assert transit('hello',port=41002)=='blocked'
    lan_access()
    api('POST','/ids/changes/ips-lab-open/rollback',{})
    status,_=api('GET','/ids/state')
    assert status['runtime']['running'] and status['failure_policy']=='closed'
    assert transit('bad-request')=='blocked'
    print('PASS: fail-open with full queue and absent listener; manual rollback restores fail-closed',flush=True)

    apply(opened,'ips-lab-crash')
    stop(agent, force=True)
    agent=launch_agent()
    status,_=api('GET','/ids/state')
    assert status['runtime']['running'] and status['failure_policy']=='closed' and not status.get('pending'), status
    assert transit('bad-request')=='blocked'
    lan_access()
    print('PASS: SIGKILL restores the confirmed NFQUEUE policy and Suricata rules',flush=True)

    apply(dict(ips, enabled=False),'ips-lab-off',30)
    status,_ = api('GET','/ids/state')
    assert not status['runtime']['running'] and not status['ips_hooked']
    assert transit('bad-request')=='echo:bad-request'
    lan_access()
    deadline = time.monotonic()+40
    while time.monotonic()<deadline:
        status,_ = api('GET','/ids/state')
        if not status.get('pending'):
            break
        time.sleep(.25)
    assert status['runtime']['running'] and status['ips_hooked'] and not status.get('pending'), status
    api('POST','/ids/changes/ips-lab-off/confirm',{},expected=409)
    assert transit('bad-request')=='blocked'
    lan_access()
    print('PASS: real 30-second timeout restores the IPS table, queue listener and signature',flush=True)
    apply(config,'ips-lab-to-ids')
    assert transit('bad-request')=='echo:bad-request'
    api('POST','/ids/changes/ips-lab-to-ids/confirm',{})
    assert 'gfw_ips' not in sh('nft','list','tables')
    print('PASS: switching to IDS removes the IPS table and preserves LAN',flush=True)
finally:
    stop(httpd)
    stop(echo)
    stop(controller)
    stop(agent)
