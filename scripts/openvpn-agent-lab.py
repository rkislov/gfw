#!/usr/bin/env python3
"""Real controller + two isolated Linux agents; no host networking changes."""
import http.client,json,os,signal,socket,subprocess,time,urllib.request,urllib.error
from pathlib import Path
ROOT=Path('/state');ARCH={'aarch64':'arm64','x86_64':'amd64'}[os.uname().machine];BIN='/work/bin/linux-'+ARCH
processes=[]
def sh(*args):
 p=subprocess.run(args,text=True,capture_output=True);assert p.returncode==0,(args,p.stderr);return p.stdout

def start(args,log):
 f=open(ROOT/log,'a');p=subprocess.Popen(args,stdout=f,stderr=f);f.close();processes.append(p);return p

def wait(fn,timeout=10):
 deadline=time.monotonic()+timeout
 while time.monotonic()<deadline:
  try:
   value=fn()
   if value:return value
  except (OSError,AssertionError,http.client.HTTPException):pass
  time.sleep(.1)
 raise AssertionError('timeout: '+str(fn))

def rootapi(sock,method,path,data=None,expected=200):
 class Conn(http.client.HTTPConnection):
  def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(90);self.sock.connect(sock)
 c=Conn('agent',timeout=90);c.request(method,'/v1'+path,None if data is None else json.dumps(data),{'Content-Type':'application/json'});r=c.getresponse();raw=r.read().decode();c.close();assert r.status==expected,(path,r.status,raw);return json.loads(raw)

def agent(which,ns=None):
 args=[BIN+'/gfw-agent','-enable-apply','-enable-openvpn','-socket','/state/'+which+'.sock','-state-dir','/state/'+which,'-lan-interface','lan0' if which=='server' else 'lan1','-management-port','8443','-openvpn-runtime','/run/ovpn/'+which]
 if ns:args=['ip','netns','exec',ns]+args
 p=start(args,which+'.log');wait(lambda:p.poll() is None and rootapi('/state/'+which+'.sock','GET','/openvpn'));return p
controller=None
TOKEN=''
def panel(which):
 global controller,TOKEN
 if controller:controller.terminate();controller.wait(timeout=10)
 controller=start([BIN+'/gfwd','-listen','127.0.0.1:8088','-data-dir','/state/control','-agent-socket','/state/'+which+'.sock'],'control.log')
 wait(lambda:urllib.request.urlopen('http://127.0.0.1:8088/healthz',timeout=1).status==200)
 TOKEN=(ROOT/'control/admin.token').read_text().strip()

def api(method,path,data=None,headers=None,expected=200):
 h={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'};h.update(headers or {})
 req=urllib.request.Request('http://127.0.0.1:8088/api/v1'+path,method=method,data=None if data is None else json.dumps(data).encode(),headers=h)
 try:r=urllib.request.urlopen(req,timeout=90)
 except urllib.error.HTTPError as e:r=e
 raw=r.read();assert r.status==expected,(path,r.status,raw.decode());return json.loads(raw) if r.headers.get_content_type()=='application/json' else raw.decode()

def save(c):
 old=api('GET','/openvpn/runtime/config');return api('PUT','/openvpn/runtime/config',c,{'If-Match':json.dumps(str(old['revision']))})
def apply(saved,id,timeout=60):return api('POST','/openvpn/runtime/apply',{'id':id,'revision':saved['revision'],'timeout_seconds':timeout})
def confirm(id):return api('POST','/openvpn/runtime/changes/'+id+'/confirm',{})
try:
 sh('ip','link','set','lo','up');sh('ip','link','add','lan0','type','veth','peer','name','mgmt0');sh('ip','netns','add','mgmt');sh('ip','link','set','mgmt0','netns','mgmt');sh('ip','addr','add','192.0.2.1/24','dev','lan0');sh('ip','link','set','lan0','up');sh('ip','netns','exec','mgmt','ip','addr','add','192.0.2.2/24','dev','mgmt0');sh('ip','netns','exec','mgmt','ip','link','set','mgmt0','up')
 sh('ip','link','add','wan0','type','veth','peer','name','lan1');sh('ip','netns','add','client');sh('ip','link','set','lan1','netns','client');sh('ip','addr','add','198.51.100.1/24','dev','wan0');sh('ip','link','set','wan0','up');sh('ip','netns','exec','client','ip','addr','add','198.51.100.2/24','dev','lan1');sh('ip','netns','exec','client','ip','link','set','lan1','up');sh('ip','netns','exec','client','ip','link','set','lo','up')
 server=agent('server');client=agent('client','client');panel('server')
 ca=api('POST','/pki/ca',{'name':'CA','common_name':'Agent VPN Root','days':365})
 def issue(name,role):return api('POST','/pki/issue',{'name':name,'ca_id':ca['id'],'common_name':name,'usage':role,'days':30,'dns_names':[name+'.home.arpa'] if role=='server' else []})
 srv=issue('server','server');cli=issue('client','client');other=issue('other','client')
 s={'id':'1'*32,'name':'Server','interface':'ovpns0','mode':'server','enabled':True,'certificate_id':srv['id'],'address':'10.80.0.1/24','bind_address':'198.51.100.1','port':1194,'protocol':'udp','clients':[{'certificate_id':cli['id'],'address':'10.80.0.2'}],'routes':[]}
 saved=save({'instances':[s]});plan=api('POST','/openvpn/runtime/plan',saved['config']);assert plan['can_apply'];apply(saved,'server-first');confirm('server-first')
 assert sh('ip','-4','addr','show','dev','ovpns0').find('10.80.0.1/24')>=0
 print('PASS: controller delivers encrypted server key + CRL, root creates owned TUN and confirms actual server',flush=True)
 c={'id':'2'*32,'name':'Client','interface':'ovpnc0','mode':'client','enabled':True,'certificate_id':cli['id'],'server_certificate_id':srv['id'],'address':'10.80.0.2/24','remote':'198.51.100.1','port':1194,'protocol':'udp','clients':[],'routes':['10.90.0.0/24']}
 panel('client');saved_client=save({'instances':[c]});assert api('POST','/openvpn/runtime/plan',saved_client['config'])['can_apply'];apply(saved_client,'client-first');confirm('client-first')
 sh('ip','netns','exec','client','ping','-c','1','-W','3','10.80.0.1')
 assert '10.90.0.0/24' in sh('ip','netns','exec','client','ip','route')
 assert api('GET','/openvpn/runtime/logs/'+c['id'])
 print('PASS: managed client pins server, connects, passes encrypted ICMP, installs explicit route and exposes bounded logs',flush=True)
 # Manual rollback with a live VPN client.
 nextc=json.loads(json.dumps(c));nextc['routes']=['10.91.0.0/24'];saved=save({'instances':[nextc]});apply(saved,'client-manual');api('POST','/openvpn/runtime/changes/client-manual/rollback',{})
 assert '10.90.0.0/24' in sh('ip','netns','exec','client','ip','route')
 # Real timer and restart must restore the confirmed client, independent of UI.
 apply(saved,'client-timeout',30);time.sleep(31);assert rootapi('/state/client.sock','GET','/openvpn')['history'][-1]['status']=='rolled_back'
 assert '10.90.0.0/24' in sh('ip','netns','exec','client','ip','route')
 apply(saved,'client-crash',60);oldpids=sh('ip','netns','pids','client').split();client.kill();client.wait();time.sleep(.5)
 for pid in oldpids:
  try:cmd=Path('/proc/'+pid+'/cmdline').read_bytes()
  except FileNotFoundError:continue
  assert b'/usr/sbin/openvpn\x00' not in cmd, 'orphan OpenVPN survived agent SIGKILL'
 client=agent('client','client');state=rootapi('/state/client.sock','GET','/openvpn');assert state['confirmed_revision']==saved_client['revision'] and not state.get('pending')
 sh('ip','netns','exec','client','ping','-c','1','-W','3','10.80.0.1')
 print('PASS: manual rollback, real 30-second timeout and SIGKILL restore confirmed client; no orphan child',flush=True)
 panel('server')
 # Confirm default-drop firewall while retaining explicit OpenVPN port/traffic.
 fw=api('GET','/config');cfg=fw['config'];cfg['rules']=[{'id':'vpn-port','name':'VPN port','enabled':True,'chain':'input','action':'accept','protocol':'udp','destination_port':1194,'family':'ipv4'},{'id':'vpn-icmp','name':'VPN ping','enabled':True,'chain':'input','action':'accept','protocol':'icmp','source':'10.80.0.0/24','family':'ipv4'}]
 fw=api('PUT','/config',cfg,{'If-Match':json.dumps(str(fw['revision']))});api('POST','/changes/apply',{'id':'vpn-firewall','revision':fw['revision'],'timeout_seconds':60});api('POST','/changes/vpn-firewall/confirm',{})
 httpd=start(['python3','-m','http.server','8443','--bind','0.0.0.0'],'http.log')
 wait(lambda:sh('ip','netns','exec','mgmt','curl','-sS','--max-time','2','http://192.0.2.1:8443/'))
 # LAN overlap/name rejection and foreign ownership must leave network intact.
 bad=json.loads(json.dumps(s));bad['interface']='lan0';saved=save({'instances':[bad]});api('POST','/openvpn/runtime/plan',saved['config'],expected=422)
 bad=json.loads(json.dumps(s));bad['address']='192.0.2.10/24';bad['clients']=[];saved=save({'instances':[bad]});api('POST','/openvpn/runtime/plan',saved['config'],expected=422)
 sh('ip','link','add','foreign0','type','dummy');bad=json.loads(json.dumps(s));bad['interface']='foreign0';saved=save({'instances':[bad]});api('POST','/openvpn/runtime/plan',saved['config'],expected=422)
 assert 'foreign0' in sh('ip','link','show','dev','foreign0')
 saved=save({'instances':[s]});apply(saved,'server-reapply');confirm('server-reapply');wait(lambda:sh('ip','netns','exec','mgmt','curl','-sS','--max-time','2','http://192.0.2.1:8443/'))
 print('PASS: LAN anti-lockout survives default-drop firewall and VPN changes; LAN overlap/name and foreign links rejected',flush=True)
 # Pending change + revocation: CRL refresh must disconnect immediately and
 # rollback must keep the newer CRL and continue denying the old client.
 pending=json.loads(json.dumps(s));pending['name']='Temporary server';saved=save({'instances':[pending]});apply(saved,'server-revoke')
 result=api('POST','/pki/certificates/'+cli['id']+'/revoke',{});assert result['crl_sync_status']=='synced',result
 api('POST','/openvpn/runtime/changes/server-revoke/rollback',{})
 state=api('GET','/openvpn/runtime/state')['agent'];assert state['runtime'][0]['crl_number']>=2
 assert not state['runtime'][0]['sessions']
 # An already issued client cannot reconnect, despite rollback to old config.
 for pid in sh('ip','netns','pids','client').split():
  try:cmd=Path('/proc/'+pid+'/cmdline').read_bytes()
  except FileNotFoundError:continue
  if cmd.startswith(b'/usr/sbin/openvpn\x00'):os.kill(int(pid),signal.SIGUSR1)
 wait(lambda:any('revoked' in x or 'hash verification failed' in x for x in api('GET','/openvpn/runtime/logs/'+s['id'])),15)
 wait(lambda:sh('ip','netns','exec','mgmt','curl','-sS','--max-time','2','http://192.0.2.1:8443/'))
 raw=(ROOT/'server/journal.json').read_text();assert 'PRIVATE KEY' not in raw and 'BEGIN CERTIFICATE' not in raw
 for p in (ROOT/'server/openvpn').glob('*.bundle'):assert b'PRIVATE KEY' not in p.read_bytes()
 print('PASS: CRL delivered during pending change, sessions disconnected, rollback retains revocation; journals/cache do not expose keys',flush=True)

 # Exercise both managed sides over TCP with another valid client.
 tcp=json.loads(json.dumps(s));tcp['protocol']='tcp';tcp['clients']=[{'certificate_id':other['id'],'address':'10.80.0.3'}]
 saved=save({'instances':[tcp]});apply(saved,'server-tcp');confirm('server-tcp')
 fw=api('GET','/config');fw['config']['rules'].append({'id':'vpn-tcp','name':'VPN TCP','enabled':True,'chain':'input','action':'accept','protocol':'tcp','family':'ipv4','destination_port':1194})
 fw=api('PUT','/config',fw['config'],{'If-Match':json.dumps(str(fw['revision']))});api('POST','/changes/apply',{'id':'tcp-firewall','revision':fw['revision'],'timeout_seconds':60});api('POST','/changes/tcp-firewall/confirm',{})
 panel('client');tc=json.loads(json.dumps(c));tc['protocol']='tcp';tc['certificate_id']=other['id'];tc['address']='10.80.0.3/24'
 saved=save({'instances':[tc]});apply(saved,'client-tcp');confirm('client-tcp');sh('ip','netns','exec','client','ping','-c','1','-W','3','10.80.0.1')
 print('PASS: actual managed TCP server and client establish encrypted tunnel',flush=True)
 panel('server');server.terminate();server.wait(timeout=12)
 revoked=api('POST','/pki/certificates/'+other['id']+'/revoke',{});assert revoked['crl_sync_status']=='pending' and revoked['crl_sync_error']
 # The job is reconstructible from durable PKI + agent confirmed settings,
 # rather than an in-memory request: restart both sides of delivery.
 panel('server');server=agent('server')
 wait(lambda:api('GET','/openvpn/runtime/state')['agent']['runtime'][0]['crl_number']>=3,25)
 assert not api('GET','/openvpn/runtime/state')['agent']['runtime'][0]['sessions']
 wait(lambda:sh('ip','netns','exec','mgmt','curl','-sS','--max-time','2','http://192.0.2.1:8443/'))
 print('PASS: offline-agent revocation is reported pending; background retry survives controller and agent restart, delivers newer CRL and preserves LAN',flush=True)
 print('ALL OPENVPN AGENT TESTS PASSED',flush=True)
finally:
 for p in reversed(processes):
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=12)
   except subprocess.TimeoutExpired:p.kill();p.wait()
