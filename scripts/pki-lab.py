#!/usr/bin/env python3
"""Actual gfwd TLS handshakes and restart recovery, using only loopback."""
import hashlib,http.client,json,os,signal,socket,ssl,subprocess,time,tempfile
from pathlib import Path
import argparse
parser=argparse.ArgumentParser();parser.add_argument('--binary',default='./bin/gfwd');args=parser.parse_args()
def unused():
 s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();return port
with tempfile.TemporaryDirectory(prefix='gfw-pki-lab-') as root:
 root=Path(root);root.chmod(0o700);cert=root/'bootstrap.crt';key=root/'bootstrap.key'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','3','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
 data=root/'data';data.mkdir(mode=0o700);token=os.urandom(32).hex();(data/'admin.token').write_text(token);(data/'admin.token').chmod(0o600)
 port=unused();challenge=unused()
 while challenge==port:challenge=unused()
 context=ssl._create_unverified_context();p=None
 log=open(root/'controller.log','w')
 def start():
  p=subprocess.Popen([args.binary,'-listen','127.0.0.1:'+str(port),'-data-dir',str(data),'-tls-cert',str(cert),'-tls-key',str(key),'-acme-listen','127.0.0.1:'+str(challenge)],stdout=log,stderr=log)
  for _ in range(200):
   assert p.poll() is None,(root/'controller.log').read_text()
   try:
    api('GET','/status');return p
   except (OSError,http.client.HTTPException):time.sleep(.05)
  raise RuntimeError('controller startup timeout')
 def api(method,path,body=None,expected=200):
  c=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=15)
  try:
   c.request(method,'/api/v1'+path,None if body is None else json.dumps(body),{'Authorization':'Bearer '+token,'Content-Type':'application/json'})
   r=c.getresponse();raw=r.read();assert r.status==expected,(method,path,r.status,raw);return json.loads(raw)
  finally:c.close()
 def fingerprint():
  with socket.create_connection(('127.0.0.1',port),timeout=5) as sock:
   with context.wrap_socket(sock,server_hostname='localhost') as tls:return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
 try:
  p=start();bootstrap=fingerprint()
  ca=api('POST','/pki/ca',{'name':'Test CA','common_name':'Test Root','days':365})
  def issue(name):return api('POST','/pki/issue',{'name':name,'ca_id':ca['id'],'common_name':'localhost','dns_names':['localhost'],'ips':['127.0.0.1'],'usage':'server','days':30})
  first=issue('First');second=issue('Second')
  api('POST','/pki/tls/apply',{'id':first['id'],'timeout_seconds':60});assert fingerprint()==first['fingerprint']
  api('POST','/pki/tls/confirm',{'id':first['id']});p.terminate();p.wait(timeout=15);p=start();assert fingerprint()==first['fingerprint']
  print('PASS: native HTTPS hot reload, fresh-handshake verification, confirmation and confirmed certificate restore',flush=True)
  api('POST','/pki/tls/apply',{'id':second['id'],'timeout_seconds':60});assert fingerprint()==second['fingerprint'];p.kill();p.wait(timeout=10);p=start();assert fingerprint()==first['fingerprint'];assert not api('GET','/pki')['tls']['pending_id']
  print('PASS: SIGKILL during TLS switch restores confirmed certificate on restart',flush=True)
  api('POST','/pki/tls/apply',{'id':second['id'],'timeout_seconds':30})
  end=time.monotonic()+40
  while time.monotonic()<end and api('GET','/pki')['tls']['pending_id']:time.sleep(.25)
  assert fingerprint()==first['fingerprint'];api('POST','/pki/tls/confirm',{'id':second['id']},422)
  print('PASS: real 30-second TLS rollback timer; late confirmation rejected',flush=True)
  c=http.client.HTTPConnection('127.0.0.1',challenge);c.request('GET','/api/v1/pki');r=c.getresponse();assert r.status==404;r.read();c.close()
  state=api('GET','/pki');serialized=json.dumps(state);assert 'PRIVATE KEY' not in serialized and 'certificate_pem' not in serialized
  api('POST','/pki/certificates/'+first['id']+'/revoke',{},422)
  print('PASS: challenge listener exposes no admin API; API omits keys; active certificate revocation blocked',flush=True)
  print('ALL PANEL PKI/TLS TESTS PASSED',flush=True)
 finally:
  if p is not None and p.poll() is None:p.terminate();p.wait(timeout=15)
  log.close()
