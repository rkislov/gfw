#!/usr/bin/env python3
"""Kernel WireGuard, actual encrypted HTTP, rollback and secret-safe API."""
import copy,configparser,json,os,runpy,subprocess,time,signal
from pathlib import Path
lab=runpy.run_path('/work/scripts/agent-lab.py');sh,start=lab['sh'],lab['start'];lab['CMD'].append('-enable-wireguard')
def api(method,path,data=None,expected=200):
 c=lab['UnixHTTP']('agent',timeout=90)
 try:
  c.request(method,'/v1'+path,None if data is None else json.dumps(data),{'Content-Type':'application/json'});r=c.getresponse();body=r.read().decode();
  if r.status!=expected:print('DIAGNOSTIC',subprocess.run(['ip','-d','-j','link','show','wg0'],capture_output=True,text=True).stdout,flush=True)
  assert r.status==expected,(path,r.status,body);return json.loads(body)
 finally:c.close()
def key(kind='tunnel'):return api('POST','/wireguard/keys',{'kind':kind})
p=None;servers=[]
try:
 p=start();server,client,psk=key(),key('client'),key('psk')
 peer={'id':'2'*32,'name':'Client','enabled':True,'public_key':client['public_key'],'key_ref':client['ref'],'psk_ref':psk['ref'],'endpoint':'','allowed_ips':['10.50.0.2/32'],'keepalive':5,'client_addresses':['10.50.0.2/32'],'client_routes':['10.50.0.0/24'],'client_dns':[]}
 tunnel={'id':'1'*32,'name':'wg0','enabled':True,'key_ref':server['ref'],'public_key':server['public_key'],'listen_port':51820,'mtu':1420,'addresses':['10.50.0.1/24'],'install_routes':True,'client_endpoint':'198.51.100.1:51820','peers':[peer]};config={'tunnels':[tunnel]}
 fw={'stateful':True,'default_input':'drop','default_forward':'drop','zones':[{'id':'lan','name':'LAN','kind':'lan','interfaces':['lan0']},{'id':'wan','name':'WAN','kind':'wan','interfaces':['wan0']}],'rules':[]}
 for id,proto,port,source,zone in [('wg-transport','udp',51820,'','wan'),('wg-http','tcp',8080,'10.50.0.2/32','')]:fw['rules'].append({'id':id,'name':id,'chain':'input','family':'ipv4','source':source,'destination':'','protocol':proto,'destination_port':port,'action':'accept','enabled':True,'source_zone':zone})
 api('POST','/firewall/apply',{'id':'wg-firewall-base','revision':10,'timeout_seconds':120,'config':fw});api('POST','/firewall/wg-firewall-base/confirm')
 def apply(c,id,timeout=120):return api('POST','/wireguard/apply',{'id':id,'revision':1,'timeout_seconds':timeout,'config':c})
 assert api('POST','/wireguard/plan',config)['can_apply'];apply(config,'wg-first-install');api('POST','/firewall/wg-first-install/rollback');assert subprocess.run(['ip','link','show','wg0'],capture_output=True).returncode!=0
 apply(config,'wg-confirmed');api('POST','/firewall/wg-confirmed/confirm')
 exported=api('POST','/wireguard/export',{'tunnel_id':tunnel['id'],'peer_id':peer['id']})['profile']
 parser=configparser.ConfigParser();parser.read_string(exported);raw='[Interface]\nPrivateKey = '+parser['Interface']['PrivateKey']+'\nListenPort = 51821\n\n[Peer]\n'+'\n'.join(k+' = '+v for k,v in parser['Peer'].items())+'\n'
 # wg setconf is case-sensitive; normalize only the standard field names.
 for a,b in [('publickey','PublicKey'),('endpoint','Endpoint'),('allowedips','AllowedIPs'),('presharedkey','PresharedKey'),('persistentkeepalive','PersistentKeepalive')]:raw=raw.replace(a+' =',b+' =')
 path=Path('/state/client.conf');path.write_text(raw);path.chmod(0o600)
 sh('ip','-n','gfw-wan','link','add','wgc','type','wireguard');sh('ip','netns','exec','gfw-wan','wg','setconf','wgc',str(path));sh('ip','-n','gfw-wan','addr','add','10.50.0.2/32','dev','wgc');sh('ip','-n','gfw-wan','link','set','wgc','up');sh('ip','-n','gfw-wan','route','add','10.50.0.0/24','dev','wgc')
 code='''import socketserver,http.server,sys
class Server(http.server.ThreadingHTTPServer):
 def server_bind(self):
  socketserver.TCPServer.server_bind(self);self.server_name='lab';self.server_port=self.server_address[1]
Server(('0.0.0.0',int(sys.argv[1])),http.server.SimpleHTTPRequestHandler).serve_forever()
'''
 for port in ['8080','8443']:servers.append(subprocess.Popen(['python3','-c',code,port],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
 sh('python3','-c',"import socket,time\nfor port in [8080,8443]:\n for _ in range(100):\n  try:\n   s=socket.create_connection(('127.0.0.1',port),.1);s.close();break\n  except OSError:time.sleep(.05)\n else:raise RuntimeError('HTTP server not ready')")
 def http(ns,url,ok=True):
  r=subprocess.run(['ip','netns','exec','gfw-'+ns,'curl','--noproxy','*','--max-time','25' if ok else '2','-fsS',url],capture_output=True,text=True);assert (r.returncode==0)==ok,(ns,url,r.returncode,r.stderr)
 http('wan','http://10.50.0.1:8080/');http('lan','http://192.0.2.1:8443/');http('wan','http://198.51.100.1:8080/',False)
 state=api('GET','/wireguard');ps=state['runtime'][0]['peers'][0];assert ps['last_handshake'] and ps['rx_bytes']>0 and ps['tx_bytes']>0;assert 'private_key' not in json.dumps(state) and 'PresharedKey' not in json.dumps(state)
 print('PASS: kernel WireGuard + PSK encrypted HTTP, routes, client export, handshake/RX/TX; LAN anti-lockout and WAN input isolation',flush=True)
 invalid=copy.deepcopy(config);invalid['tunnels'][0]['addresses']=['192.0.2.99/24'];api('POST','/wireguard/plan',invalid,422)
 invalid=copy.deepcopy(config);invalid['tunnels'][0]['peers'][0]['allowed_ips']=['192.0.2.0/24'];invalid['tunnels'][0]['peers'][0]['client_addresses']=[];api('POST','/wireguard/plan',invalid,422)
 sh('ip','link','add','wgforeign','type','wireguard');invalid=copy.deepcopy(config);invalid['tunnels'][0]['name']='wgforeign';api('POST','/wireguard/plan',invalid,422)
 protected=copy.deepcopy(fw);protected['zones'].append({'id':'vpn','name':'VPN','kind':'vpn','interfaces':['wg0']});api('POST','/firewall/apply',{'id':'wg-zone-test','revision':11,'timeout_seconds':120,'config':protected});api('POST','/firewall/wg-zone-test/confirm');api('POST','/wireguard/plan',{'tunnels':[]},422)
 print('PASS: LAN/address/route overlaps, foreign ownership and confirmed zone dependencies reject unsafe changes',flush=True)
 changed=copy.deepcopy(config);changed['tunnels'][0]['listen_port']=51822;apply(changed,'wg-crash');p.kill();p.wait(timeout=30);p=start();assert api('GET','/wireguard')['confirmed']['tunnels'][0]['listen_port']==51820;http('wan','http://10.50.0.1:8080/')
 print('PASS: SIGKILL restores keys, peer/PSK, addresses and routes from confirmed journal',flush=True)
 apply(changed,'wg-timer',30);api('POST','/wireguard/apply',{'id':'wg-overlap','revision':2,'timeout_seconds':30,'config':config},409)
 end=time.monotonic()+40
 while time.monotonic()<end and 'pending' in api('GET','/wireguard'):time.sleep(.25)
 assert 'pending' not in api('GET','/wireguard');api('POST','/firewall/wg-timer/confirm',expected=409);http('wan','http://10.50.0.1:8080/');http('lan','http://192.0.2.1:8443/')
 print('PASS: real 30-second WireGuard rollback timer, late confirmation rejection, encrypted traffic restored',flush=True)
 p.terminate();p.wait(timeout=30);p=None;sh('ip','link','del','wg0');p=start();http('wan','http://10.50.0.1:8080/');sh('ip','link','show','wgforeign');sh('nft','list','table','inet','external_test')
 print('PASS: confirmed WireGuard restored after simulated empty kernel; foreign interface/table preserved',flush=True)
 print('ALL WIREGUARD TESTS PASSED',flush=True)
finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=30)
 for server in servers:server.terminate();server.wait(timeout=5)
