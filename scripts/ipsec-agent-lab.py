#!/usr/bin/env python3
"""Real controller + two isolated Linux agents; no host networking changes."""
import http.client,json,os,signal,socket,subprocess,time,urllib.request,urllib.error
from pathlib import Path
if os.environ.get("GFW_IPSEC_LAB") != "1":
 raise SystemExit("Use the isolated IPsec lab runner")
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
 args=[BIN+'/gfw-agent','-enable-apply','-enable-ipsec','-socket','/state/'+which+'.sock','-state-dir','/state/'+which,'-lan-interface','lan0' if which=='server' else 'lan1','-management-port','8443','-ipsec-runtime','/run/ike/'+which]
 if ns:
  # Separate /run for ALT charon's compiled-in PID file.
  args=['ip','netns','exec',ns,'unshare','-m','sh','-ec','mount --make-rprivate /; mount -t tmpfs tmpfs /run; exec "$@"','sh']+args
 p=start(args,which+'.log');wait(lambda:p.poll() is None and rootapi('/state/'+which+'.sock','GET','/ipsec'));return p
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
 old=api('GET','/ipsec/config');return api('PUT','/ipsec/config',c,{'If-Match':json.dumps(str(old['revision']))})
def apply(saved,id,timeout=60):return api('POST','/ipsec/apply',{'id':id,'revision':saved['revision'],'timeout_seconds':timeout})
def confirm(id):return api('POST','/ipsec/changes/'+id+'/confirm',{})
try:
 sh('ip','link','set','lo','up')
 sh('ip','netns','add','mgmt')
 sh('ip','link','add','lan0','type','veth','peer','name','mgmt0','netns','mgmt')
 sh('ip','addr','add','192.0.2.1/24','dev','lan0')
 sh('ip','link','set','lan0','up')
 sh('ip','netns','exec','mgmt','ip','addr','add','192.0.2.2/24','dev','mgmt0')
 sh('ip','netns','exec','mgmt','ip','link','set','mgmt0','up')
 sh('ip','netns','add','client')
 sh('ip','link','add','wan0','type','veth','peer','name','lan1','netns','client')
 sh('ip','addr','add','198.51.100.1/24','dev','wan0')
 sh('ip','link','set','wan0','up')
 sh('ip','netns','exec','client','ip','addr','add','198.51.100.2/24','dev','lan1')
 sh('ip','netns','exec','client','ip','link','set','lan1','up')
 sh('ip','netns','exec','client','ip','link','set','lo','up')
 sh('ip','addr','add','10.81.0.1/32','dev','lo')
 sh('ip','netns','exec','client','ip','addr','add','10.82.0.1/32','dev','lo')
 server=agent('server')
 client=agent('client','client')
 panel('server')
 ca=api('POST','/pki/ca',{'name':'IKE Lab CA','common_name':'IKE Lab Root','days':365})
 def issue(name):
  return api('POST','/pki/issue',{'name':name,'ca_id':ca['id'],'common_name':name,'usage':'server','days':30,'dns_names':[name+'.home.arpa']})
 left=issue('left')
 right=issue('right')
 s={'id':'1'*32,'name':'Responder','interface':'ikeleft','enabled':True,'initiate':False,
    'local_address':'198.51.100.1','remote_address':'198.51.100.2',
    'local_networks':['10.81.0.0/24'],'remote_networks':['10.82.0.0/24'],
    'certificate_id':left['id'],'peer_certificate_id':right['id']}
 c={'id':'2'*32,'name':'Initiator','interface':'ikeright','enabled':True,'initiate':True,
    'local_address':'198.51.100.2','remote_address':'198.51.100.1',
    'local_networks':['10.82.0.0/24'],'remote_networks':['10.81.0.0/24'],
    'certificate_id':right['id'],'peer_certificate_id':left['id']}
 saved=save({'tunnels':[s]})
 assert api('POST','/ipsec/plan',saved['config'])['can_apply']
 apply(saved,'ipsec-left')
 confirm('ipsec-left')
 print('PASS: IKEv2 responder configured through API',flush=True)
 panel('client')
 saved=save({'tunnels':[c]})
 apply(saved,'ipsec-right')
 confirm('ipsec-right')
 def ping():
  return sh('ip','netns','exec','client','ping','-I','10.82.0.1','-c','1','-W','1','10.81.0.1')
 wait(ping,15)
 assert api('GET','/ipsec/state')['agent']['runtime'][0]['established']
 assert api('GET','/ipsec/logs')
 assert 'if_id' in sh('ip','xfrm','policy')
 print('PASS: mutual CA authentication, XFRM routes, encrypted ICMP, SA state and logs',flush=True)
 replacement=issue('right')
 wrong=save({'tunnels':[dict(c,certificate_id=replacement['id'])]})
 apply(wrong,'ipsec-wrong-cert')
 for _ in range(5):
  attempt=subprocess.run(['ip','netns','exec','client','ping','-I','10.82.0.1','-c','1','-W','1','10.81.0.1'],capture_output=True)
  assert attempt.returncode!=0,'a different peer certificate established a working tunnel'
 assert not api('GET','/ipsec/state')['agent']['runtime'][0]['established']
 api('POST','/ipsec/changes/ipsec-wrong-cert/rollback',{})
 wait(ping,15)
 print('PASS: a second certificate from the same CA and with the same CN is rejected',flush=True)

 panel('server')
 fw=api('GET','/config')
 cfg=fw['config']
 cfg['rules']=[{'id':f'ike-{port}','name':f'IKE {port}','enabled':True,'chain':'input',
                'action':'accept','protocol':'udp','destination_port':port,'family':'ipv4'}
               for port in (500,4500)]
 cfg['rules'].append({'id':'vpn-ping','name':'VPN ICMP','enabled':True,'chain':'input',
                      'action':'accept','protocol':'icmp','source':'10.82.0.0/24','family':'ipv4'})
 fw=api('PUT','/config',cfg,{'If-Match':json.dumps(str(fw['revision']))})
 api('POST','/changes/apply',{'id':'ipsec-filter','revision':fw['revision'],'timeout_seconds':60})
 api('POST','/changes/ipsec-filter/confirm',{})
 httpd=start(['python3','-m','http.server','8443','--bind','0.0.0.0'],'http.log')
 def lan():
  return sh('ip','netns','exec','mgmt','curl','-fsS','--max-time','2','http://192.0.2.1:8443/')
 wait(lan)
 wait(ping)
 for altered in [dict(s,interface='lan0'),dict(s,remote_networks=['192.0.2.0/24'])]:
  bad=save({'tunnels':[altered]})
  api('POST','/ipsec/plan',bad['config'],expected=422)
 print('PASS: LAN anti-lockout, protected interface and overlap checks',flush=True)
 pending=save({'tunnels':[dict(s,name='Temporary') ]})
 apply(pending,'ipsec-timeout',30)
 wait(lambda:not api('GET','/ipsec/state')['agent'].get('pending'),40)
 assert api('GET','/ipsec/state')['agent']['history'][-1]['status']=='rolled_back'
 wait(lan)
 apply(pending,'ipsec-crash')
 server.kill()
 server.wait(timeout=5)
 server=agent('server')
 result=api('GET','/ipsec/state')['agent']
 assert not result.get('pending')
 assert result['confirmed']['tunnels'][0]['name']=='Responder'
 wait(lan)
 print('PASS: timeout and SIGKILL restore confirmed configuration and preserve LAN',flush=True)
 apply(pending,'ipsec-revoke')
 revocation=api('POST','/pki/certificates/'+right['id']+'/revoke',{})
 assert revocation['crl_sync_status']=='synced',revocation
 api('POST','/ipsec/changes/ipsec-revoke/rollback',{})
 result=api('GET','/ipsec/state')['agent']['runtime'][0]
 assert result['blocked'] and result['crl_number']>=2 and not result['established']
 assert '10.82.0.0/24 dev ikeleft' in sh('ip','route')
 assert 'if_id' not in sh('ip','xfrm','policy')
 wait(lan)
 journal=(ROOT/'server/journal.json').read_text()
 assert 'PRIVATE KEY' not in journal and 'BEGIN CERTIFICATE' not in journal
 print('PASS: revocation stops SAs, survives rollback and keeps the XFRM route closed',flush=True)
 print('ALL IPSEC AGENT TESTS PASSED',flush=True)
except Exception:
 for which in ('server','client'):
  try:
   lines=rootapi('/state/'+which+'.sock','GET','/ipsec/logs')
   print(which,'IKE journal:',*lines[-40:],sep='\n',flush=True)
  except Exception:
   path=ROOT/(which+'.log')
   if path.exists():print(path.read_text()[-3000:],flush=True)
 raise
finally:
 for process in reversed(processes):
  if process.poll() is None:
   process.terminate()
   try:process.wait(timeout=12)
   except subprocess.TimeoutExpired:
    process.kill()
    process.wait()
