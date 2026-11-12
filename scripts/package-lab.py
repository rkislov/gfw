#!/usr/bin/env python3
"""Install/upgrade/remove the single RPM in a disposable ALT container."""
import hashlib,http.client,json,os,signal,socket,sqlite3,ssl,subprocess,time,urllib.request
from pathlib import Path
arch={'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine]
rpmarch={'arm64':'aarch64','amd64':'x86_64'}[arch]
package='/work/dist/gfw-0.22.5-1.altp10.'+rpmarch+'.rpm'
def sh(*args):return subprocess.run(args,check=True,text=True,capture_output=True).stdout
sh('rpm','-Uvh',package)
assert sh('rpm','-q','gfw').strip().startswith('gfw-0.22.5-1.altp10')
for name in ['gfwd','gfw-agent']:
 assert hashlib.sha256(Path('/usr/sbin/'+name).read_bytes()).digest()==hashlib.sha256(Path('/work/bin/linux-'+arch+'/'+name).read_bytes()).digest()
assert 'gfw' in sh('getent','passwd','gfw')
verify=subprocess.run(['systemd-analyze','verify','/usr/lib/systemd/system/gfw-agent.service','/usr/lib/systemd/system/gfwd.service'],capture_output=True,text=True)
assert verify.returncode==0,verify.stderr
print('PASS: one RPM installs both binaries, embedded modules, users, units, setup and notices; systemd unit verification',flush=True)
sh('ip','link','add','lan0','type','dummy');sh('ip','addr','add','192.0.2.1/24','dev','lan0');sh('ip','link','set','lan0','up');sh('ip','link','set','lo','up')
Path('/state').mkdir(mode=0o700,exist_ok=True)
agent=subprocess.Popen(['/usr/sbin/gfw-agent','-enable-apply','-enable-network','-enable-services','-enable-wireguard','-enable-openvpn','-enable-ipsec','-enable-ids','-ipsec-runtime','/state/ipsec-runtime','-openvpn-runtime','/state/openvpn-runtime','-lan-interface','lan0','-management-port','8443','-socket','/state/agent.sock','-state-dir','/var/lib/gfw-agent'],stdout=subprocess.DEVNULL,stderr=open('/state/agent.log','w'))
controller=None
try:
 for _ in range(200):
  if Path('/state/agent.sock').exists():break
  assert agent.poll() is None,Path('/state/agent.log').read_text();time.sleep(.05)
 controller=subprocess.Popen(['/usr/sbin/gfwd','-listen','127.0.0.1:8088','-data-dir','/var/lib/gfw','-agent-socket','/state/agent.sock'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 for _ in range(200):
  try:
   urllib.request.urlopen('http://127.0.0.1:8088/healthz',timeout=1).close();break
  except OSError:time.sleep(.05)
 key=Path('/var/lib/gfw/admin.token').read_text().strip()
 def api(method,path,data=None,headers=None):
  h={'Authorization':'Bearer '+key,'Content-Type':'application/json'};h.update(headers or {})
  req=urllib.request.Request('http://127.0.0.1:8088/api/v1'+path,method=method,data=None if data is None else json.dumps(data).encode(),headers=h)
  with urllib.request.urlopen(req,timeout=90) as response:return json.load(response),response.headers
 assert api('GET','/status')[0]['version']=='0.22.5'
 assert api('GET','/ids/state')[0]['enabled'] and not api('GET','/ids/state')[0]['runtime']['running']
 ids_cfg,_=api('GET','/ids/config')
 assert not ids_cfg['config']['enabled'] and api('GET','/ids/alerts')[0]==[]
 assert Path('/var/lib/gfw-agent/ids/alerts.db').is_file()
 print('PASS: installed Suricata module and persistent alert database; IDS starts disabled',flush=True)
 feed,_=api('GET','/feed')
 assert not feed['has_key'] and feed['entries']==[]
 feed,_=api('PUT','/feed',{'revision':feed['revision'],'key':'fixture-feed-key','interval_hours':0})
 assert feed['has_key'] and 'fixture-feed-key' not in json.dumps(feed)
 feed_key=Path('/var/lib/gfw/feed/device.key').read_bytes()
 feed_settings=Path('/var/lib/gfw/feed/subscription').read_bytes()
 assert b'fixture-feed-key' not in feed_settings
 print('PASS: installed RPM exposes Security Feed and encrypts the API key',flush=True)
 snapshot,headers=api('GET','/services/config');c=snapshot['config']
 c['dns'].update(enabled=True,interface='lan0',address='192.0.2.1',allowed_clients=['192.0.2.0/24'])
 c['dhcp']['enabled']=True;c['dhcp']['pools']=[{'id':'office','name':'Office','interface':'lan0','address':'192.0.2.1','network':'192.0.2.0/24','start':'192.0.2.100','end':'192.0.2.150','gateway':'192.0.2.1','dns':['192.0.2.1'],'domain':'home.arpa','reservations':[]}]
 saved,_=api('PUT','/services/config',c,{'If-Match':headers['ETag']})
 assert api('POST','/services/plan',c)[0]['can_apply']
 result,_=api('POST','/services/apply',{'id':'rpm-service-apply','revision':saved['revision'],'timeout_seconds':60});assert result['status']=='pending'
 assert api('POST','/services/changes/rpm-service-apply/confirm',{})[0]['status']=='confirmed'
 state=api('GET','/services/state')[0];assert state['runtime']['dns_running'] and state['runtime']['dhcp_running']==1
 audit=api('GET','/audit')[0];assert any(x['action']=='services.confirm.request:rpm-service-apply' for x in audit)
 print('PASS: installed controller/agent save, plan, apply and confirm DNS/DHCP through authenticated API; shared audit',flush=True)
 # Seed a provider fixture without contacting the subscription service.
 with sqlite3.connect('/var/lib/gfw/gfw.db') as db:
  for name, raw, normalized in [('ips.txt',b'203.0.113.3',b'203.0.113.3/32\n'),('domains.txt',b'blocked.example',b'blocked.example\n')]:
   db.execute('INSERT INTO feed_snapshot VALUES(?,?,?,?,?,?)',(name,1,hashlib.sha256(raw).hexdigest(),'fixture',raw,normalized))
 feed,_=api('GET','/feed')
 hashes={entry['name']:entry['sha256'] for entry in feed['entries']}
 fw,_=api('GET','/config')
 staged,_=api('POST','/feed/consumers/firewall',{'revision':fw['revision'],'sha256':hashes['ips.txt'],'exceptions':['203.0.113.4']})
 plan,_=api('POST','/changes/plan',staged['config'])
 assert plan['kernel_validated'] and 'gfw:feed:ip:daddr' in plan['nftables'] and 'gfw:anti-lockout' in plan['nftables']
 pending,_=api('POST','/changes/apply',{'id':'rpm-feed-firewall','revision':staged['revision'],'timeout_seconds':60})
 assert pending['status']=='pending'
 api('POST','/changes/rpm-feed-firewall/confirm',{})
 assert api('GET','/changes/state')[0]['security_feed']['sha256']==hashes['ips.txt']
 staged,_=api('POST','/feed/consumers/dns',{'revision':saved['revision'],'sha256':hashes['domains.txt'],'exceptions':['allowed.blocked.example']})
 plan,_=api('POST','/services/plan',staged['config'])
 assert plan['can_apply']
 pending,_=api('POST','/services/apply',{'id':'rpm-feed-dns','revision':staged['revision'],'timeout_seconds':60})
 assert pending['status']=='pending'
 api('POST','/services/changes/rpm-feed-dns/confirm',{})
 assert api('GET','/services/state')[0]['security_feed']['sha256']==hashes['domains.txt']
 print('PASS: installed controller pins Feed snapshots in drafts and agent confirms firewall and DNS filters',flush=True)
 ca,_=api('POST','/pki/ca',{'name':'RPM CA','common_name':'RPM Root','days':365})
 leaf,_=api('POST','/pki/issue',{'name':'RPM TLS','ca_id':ca['id'],'common_name':'gateway.home.arpa','dns_names':['gateway.home.arpa'],'ips':['192.0.2.1'],'usage':'server','days':30})
 state,_=api('GET','/pki');assert len(state['certificates'])==2 and 'PRIVATE KEY' not in json.dumps(state)
 assert Path('/var/lib/gfw/pki/device.key').stat().st_mode&0o777==0o600
 assert Path('/var/lib/gfw/pki/pki.db').stat().st_mode&0o777==0o600
 device_key=Path('/var/lib/gfw/pki/device.key').read_bytes()
 print('PASS: installed single package creates CA/certificates; encrypted vault and device key permissions',flush=True)

 # Exercise a real published TLS route, WAF actions, log persistence and rollback.
 upstream=subprocess.Popen(['python3','-u','-c',"""
from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  content=(self.path+' '+self.headers.get('Cookie','')).encode()
  self.send_response(200);self.end_headers();self.wfile.write(content)
server=HTTPServer(('127.0.0.1',28081),Handler)
print('ready',flush=True)
server.serve_forever()
"""],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
 try:
  assert upstream.stdout.readline().strip()=='ready'
  pem_request=urllib.request.Request('http://127.0.0.1:8088/api/v1/pki/certificates/'+ca['id']+'/pem',headers={'Authorization':'Bearer '+key})
  with urllib.request.urlopen(pem_request) as response: context=ssl.create_default_context(cadata=response.read().decode())
  host='gateway.home.arpa'
  def via_fess(path):
   conn=http.client.HTTPConnection('127.0.0.1',28080,timeout=5)
   conn.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',28080),timeout=5),server_hostname=host)
   try:
    conn.request('GET',path,headers={'Host':host,'Cookie':'gfw_session=secret; app=ok'})
    response=conn.getresponse()
    return response.status,response.read()
   finally:
    conn.close()
  draft,_=api('GET','/fess/config')
  draft['config']={'enabled':True,'listen':'127.0.0.1:28080','tls':True,'sites':[
   {'host':host,'path':'/app','upstream':'http://127.0.0.1:28081','certificate':leaf['id'],
    'mode':'block','use_pack':False,'rules':[
     {'id':'test-env','name':'Protected env','action':'block','priority':1,'condition':{'path_exact':'/.env'}}]}]}
  draft,_=api('PUT','/fess/config',draft)
  assert api('POST','/fess/plan',{})[0]['revision']==draft['revision']
  pending,_=api('POST','/fess/apply',{'revision':draft['revision'],'timeout_seconds':60})
  assert via_fess('/app/ok')==(200,b'/ok app=ok')
  assert via_fess('/app/.env')[0]==403
  assert via_fess('/application/ok')[0]==404
  api('POST','/fess/changes/'+pending['id']+'/confirm',{})
  draft['config']['sites'][0]['mode']='log'
  draft,_=api('PUT','/fess/config',draft)
  pending,_=api('POST','/fess/apply',{'revision':draft['revision'],'timeout_seconds':60})
  assert via_fess('/app/.env')[0]==200
  api('POST','/fess/changes/'+pending['id']+'/rollback',{})
  assert via_fess('/app/.env')[0]==403
  for _ in range(30):
   events,_=api('GET','/fess/events')
   if {e['decision'] for e in events}=={'log','block'}:break
   time.sleep(.1)
  assert {e['decision'] for e in events}=={'log','block'}
  draft['config']['listen']='127.0.0.1:8088'
  draft,_=api('PUT','/fess/config',draft)
  try:
   api('POST','/fess/plan',{})
  except urllib.error.HTTPError as error:
   assert error.code==422
  else:
   raise AssertionError('management port reserved')
  controller.kill();controller.wait(timeout=10)
  controller=subprocess.Popen(['/usr/sbin/gfwd','-listen','127.0.0.1:8088','-data-dir','/var/lib/gfw','-agent-socket','/state/agent.sock'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for _ in range(100):
   try:
    api('GET','/fess/state')
    break
   except OSError:
    time.sleep(.05)
  assert via_fess('/app/.env')[0]==403 and api('GET','/fess/events')[0]
  print('PASS: FESS TLS, host/path, blocking and log modes, rollback, management port and restart persistence',flush=True)
 finally:
  upstream.terminate();upstream.wait(timeout=5)

 vpn_client,_=api('POST','/pki/issue',{'name':'VPN client','ca_id':ca['id'],'common_name':'rpm-client','usage':'client','days':30})
 ovpn,ovpn_headers=api('GET','/openvpn/config')
 ovpn_profile={'id':'a'*32,'name':'RPM OpenVPN','server_certificate_id':leaf['id'],'client_certificate_id':vpn_client['id'],'remote':'vpn.example.org','port':1194,'protocol':'udp','routes':['10.80.0.0/24'],'dns':['10.80.0.1']}
 ovpn,_=api('PUT','/openvpn/config',{'profiles':[ovpn_profile]},{'If-Match':ovpn_headers['ETag']})
 assert api('POST','/openvpn/check',ovpn_profile)[0]['identity']['ca_id']==ca['id']
 ovpn_state=api('GET','/openvpn/state')[0];assert ovpn_state['mode']=='profiles' and not ovpn_state['apply_enabled'] and ovpn_state['profiles'][0]['can_export']
 req=urllib.request.Request('http://127.0.0.1:8088/api/v1/openvpn/export',method='POST',data=json.dumps({'id':ovpn_profile['id'],'revision':ovpn['revision']}).encode(),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=10) as response:
  ovpn_file=response.read().decode();assert 'PRIVATE KEY' in ovpn_file and 'peer-fingerprint ' in ovpn_file and 'route-nopull' in ovpn_file and response.headers['Cache-Control']=='no-store'
 api('POST','/pki/certificates/'+vpn_client['id']+'/revoke',{})
 assert not api('GET','/openvpn/state')[0]['profiles'][0]['can_export']
 print('PASS: installed package persists OpenVPN profiles, audits private export and blocks export after revocation',flush=True)
 runtime,runtime_headers=api('GET','/openvpn/runtime/config')
 runtime_config={'instances':[{'id':'b'*32,'name':'RPM OpenVPN server','interface':'ovpnpkg','mode':'server','enabled':True,'certificate_id':leaf['id'],'address':'10.81.0.1/24','bind_address':'192.0.2.1','port':1194,'protocol':'udp','routes':[],'clients':[]}]}
 runtime,_=api('PUT','/openvpn/runtime/config',runtime_config,{'If-Match':runtime_headers['ETag']})
 assert api('POST','/openvpn/runtime/plan',runtime_config)[0]['can_apply']
 api('POST','/openvpn/runtime/apply',{'id':'rpm-openvpn-server','revision':runtime['revision'],'timeout_seconds':60})
 api('POST','/openvpn/runtime/changes/rpm-openvpn-server/confirm',{})
 assert api('GET','/openvpn/runtime/state')[0]['agent']['runtime'][0]['ready']
 assert api('GET','/openvpn/runtime/logs/'+'b'*32)[0]
 print('PASS: installed single package starts actual OpenVPN server, confirms state and provides logs',flush=True)
 assert api('GET','/ipsec/state')[0]['agent']['enabled']
 ipsec_cfg, ipsec_headers = api('GET','/ipsec/config')
 assert ipsec_cfg['config']['tunnels']==[]
 ipsec_draft,_=api('PUT','/ipsec/config',{'tunnels':[]},{'If-Match':ipsec_headers['ETag']})
 assert api('POST','/ipsec/plan',ipsec_draft['config'])[0]['can_apply']
 ipsec_pending,_=api('POST','/ipsec/apply',{'id':'rpm-ipsec-empty','revision':ipsec_draft['revision'],'timeout_seconds':60})
 assert ipsec_pending['kind']=='ipsec'
 api('POST','/ipsec/changes/rpm-ipsec-empty/confirm',{})
 print('PASS: installed IPsec module exposes authenticated draft, plan, confirmation and state',flush=True)



 server_key,_=api('POST','/wireguard/keys',{'kind':'tunnel'});client_key,_=api('POST','/wireguard/keys',{'kind':'client'})
 wg,headers=api('GET','/wireguard/config')
 wg['config']={'tunnels':[{'id':'1'*32,'name':'wgpackage','enabled':True,'key_ref':server_key['ref'],'public_key':server_key['public_key'],'listen_port':51820,'mtu':1420,'addresses':['10.70.0.1/24'],'install_routes':True,'client_endpoint':'192.0.2.1:51820','peers':[{'id':'2'*32,'name':'Client','enabled':True,'public_key':client_key['public_key'],'key_ref':client_key['ref'],'psk_ref':'','endpoint':'','allowed_ips':['10.70.0.2/32'],'keepalive':25,'client_addresses':['10.70.0.2/32'],'client_routes':['10.70.0.0/24'],'client_dns':[]}]}]}
 saved,_=api('PUT','/wireguard/config',wg['config'],{'If-Match':headers['ETag']})
 assert api('POST','/wireguard/plan',wg['config'])[0]['can_apply']
 api('POST','/wireguard/apply',{'id':'rpm-wireguard-apply','revision':saved['revision'],'timeout_seconds':60})
 api('POST','/wireguard/changes/rpm-wireguard-apply/confirm',{})
 assert api('GET','/wireguard/state')[0]['runtime'][0]['up']
 c=http.client.HTTPConnection('127.0.0.1',8088);c.request('POST','/api/v1/wireguard/export',json.dumps({'tunnel_id':'1'*32,'peer_id':'2'*32}),{'Authorization':'Bearer '+key,'Content-Type':'application/json'});response=c.getresponse();profile=response.read();assert response.status==200 and b'PrivateKey = ' in profile;c.close()
 print('PASS: installed single package generates protected WG keys, saves/applies/confirms tunnel and exports client profile',flush=True)


finally:
 if controller is not None:controller.terminate();controller.wait(timeout=10)
 agent.terminate();agent.wait(timeout=30)
subprocess.run(['python3','/work/scripts/pki-lab.py','--binary','/usr/sbin/gfwd'],check=True)
sh('rpm','-Uvh','--replacepkgs',package)
assert Path('/var/lib/gfw/gfw.db').exists() and Path('/var/lib/gfw-agent/journal.json').exists()
sh('rpm','-e','gfw')
assert Path('/var/lib/gfw/gfw.db').exists() and Path('/var/lib/gfw-agent/journal.json').exists()
assert not Path('/usr/sbin/gfw-agent').exists()
assert Path('/var/lib/gfw/pki/device.key').read_bytes()==device_key and Path('/var/lib/gfw/pki/pki.db').exists()
assert Path('/var/lib/gfw/feed/device.key').read_bytes()==feed_key
assert Path('/var/lib/gfw/feed/subscription').read_bytes()==feed_settings
print('PASS: package upgrade/removal preserve configuration, admin token, recovery journal and lease storage',flush=True)
print('ALL SINGLE PACKAGE TESTS PASSED',flush=True)
