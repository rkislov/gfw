#!/usr/bin/env python3
"""Real DNS/DHCP traffic and recovery; disposable ALT p10 container only."""
import copy,json,runpy,subprocess,time,signal,socket
lab=runpy.run_path('/work/scripts/agent-lab.py')
sh,start=[lab[k] for k in ('sh','start')]
lab['CMD'].extend(['-enable-services','-enable-network'])
lab['peer']('dmz','203.0.113','2001:db8:3')
class UnixHTTP(lab['UnixHTTP']):pass
def api(method,path,data=None,expected=200):
 c=UnixHTTP('agent',timeout=90)
 try:
  c.request(method,'/v1'+path,None if data is None else json.dumps(data),{'Content-Type':'application/json'})
  r=c.getresponse();body=r.read().decode();assert r.status==expected,(method,path,r.status,body);return json.loads(body)
 finally:c.close()
p=None
try:
 p=start()
 network={'interfaces':[{'name':'dmz0','type':'physical','parent':'','vlan':0,'members':[],'bond_mode':'','mtu':1500,'up':True,'addresses':['203.0.113.1/24','2001:db8:3::1/64'],'adopt':True},{'name':'dmz.100','type':'vlan','parent':'dmz0','vlan':100,'members':[],'bond_mode':'','mtu':1500,'up':True,'addresses':['10.90.0.1/24'],'adopt':False}],'routes':[]}
 api('POST','/network/apply',{'id':'services-vlan','revision':1,'timeout_seconds':120,'config':network});api('POST','/firewall/services-vlan/confirm')
 sh('ip','-n','gfw-dmz','link','add','link','dmz-client','name','client100','type','vlan','id','100')
 sh('ip','-n','gfw-dmz','addr','add','10.90.0.2/24','dev','client100');sh('ip','-n','gfw-dmz','link','set','client100','up')
 firewall={'default_input':'drop','default_forward':'drop','stateful':False,'rules':[],'zones':[{'id':x,'name':x,'kind':x,'interfaces':[('dmz.100' if x=='dmz' else x+'0')]} for x in ['lan','wan','dmz']]}
 for id,zone,proto,port in [('dns-tcp','lan','tcp',53),('dns-udp','lan','udp',53),('dhcp-lan','lan','udp',67),('dhcp-dmz','dmz','udp',67)]:
  firewall['rules'].append({'id':id,'name':id,'chain':'input','family':'ipv4','source':'','destination':'','protocol':proto,'destination_port':port,'action':'accept','enabled':True,'source_zone':zone})
 api('POST','/firewall/apply',{'id':'services-firewall','revision':10,'timeout_seconds':120,'config':firewall});api('POST','/firewall/services-firewall/confirm')
 cfg=api('GET','/services')['confirmed']
 cfg['dns'].update(enabled=True,interface='lan0',address='192.0.2.1',allowed_clients=['192.0.2.0/24'],zones=[{'name':'home.arpa.','records':['home.arpa. 300 IN SOA ns.home.arpa. hostmaster.home.arpa. 1 3600 600 86400 300','home.arpa. 300 IN NS ns.home.arpa.','ns.home.arpa. 300 IN A 192.0.2.1','router.home.arpa. 300 IN A 192.0.2.1']}])
 cfg['dhcp']['enabled']=True
 cfg['dhcp']['pools']=[{'id':z,'name':z,'interface':('dmz.100' if z=='dmz' else z+'0'),'address':prefix+'.1','network':prefix+'.0/24','start':prefix+'.100','end':prefix+'.150','gateway':prefix+'.1','dns':['192.0.2.1'],'domain':'home.arpa','reservations':[{'mac':'02:11:22:33:44:55','ip':prefix+'.20','hostname':'printer'}]} for z,prefix in [('lan','192.0.2'),('dmz','10.90.0')]]
 def apply(c,id,timeout=120):return api('POST','/services/apply',{'id':id,'revision':20,'timeout_seconds':timeout,'config':c})
 apply(cfg,'services-first')
 api('POST','/firewall/apply',{'id':'services-overlap','revision':11,'timeout_seconds':120,'config':firewall},409)
 dnsclient=r'''import socket,struct,sys
server=sys.argv[1];transport=sys.argv[2];name='router.home.arpa'
q=struct.pack('!HHHHHH',1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM);s.settimeout(2)
if transport=='tcp':
 s.connect((server,53));s.sendall(struct.pack('!H',len(q))+q)
 def read(n):
  out=b''
  while len(out)<n:
   part=s.recv(n-len(out))
   if not part:raise RuntimeError('short TCP DNS response')
   out+=part
  return out
 data=read(struct.unpack('!H',read(2))[0])
else:s.sendto(q,(server,53));data=s.recv(65535)
assert struct.unpack('!H',data[6:8])[0]>0 and data[-4:]==socket.inet_aton('192.0.2.1'),data
print('DNS OK')
'''
 for transport in ['udp','tcp']:assert 'DNS OK' in sh('ip','netns','exec','gfw-lan','python3','-c',dnsclient,'192.0.2.1',transport)
 print('PASS: embedded Go DNS authoritative zone answers real UDP/TCP queries',flush=True)
 dhcpclient=r'''import socket,struct,time,sys,json
iface,server,expected=sys.argv[1:4]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.setsockopt(socket.SOL_SOCKET,25,iface.encode()+b'\0');s.bind(('',68));s.settimeout(2)
xid=0x12345678;mac=bytes.fromhex('021122334455')
base=struct.pack('!BBBBIHHIIII16s64s128s',1,1,6,0,xid,0,0x8000,0,0,0,0,mac+b'\0'*10,b'\0'*64,b'\0'*128)+bytes.fromhex('63825363')
def exchange(kind,extra=b''):
 payload=base+bytes([53,1,kind])+extra+bytes([255]);payload=payload.ljust(300,b'\0');s.sendto(payload,('255.255.255.255',67))
 while True:
  raw,_=s.recvfrom(4096)
  if raw[0]!=2 or struct.unpack('!I',raw[4:8])[0]!=xid:continue
  opts={};i=240
  while i<len(raw):
   code=raw[i];i+=1
   if code==255:break
   if code==0:continue
   n=raw[i];i+=1;opts[code]=raw[i:i+n];i+=n
  return raw,opts
r,o=exchange(1);assert o[53]==b'\x02' and socket.inet_ntoa(r[16:20])==expected and socket.inet_ntoa(o[54])==server,(r,o)
r,o=exchange(3,bytes([50,4])+socket.inet_aton(expected)+bytes([54,4])+socket.inet_aton(server));assert o[53]==b'\x05' and socket.inet_ntoa(r[16:20])==expected
assert socket.inet_ntoa(o[6][:4])=='192.0.2.1'
print(json.dumps({'ip':expected,'dns':socket.inet_ntoa(o[6][:4]),'lease':struct.unpack('!I',o[51])[0]}))
'''
 for z,prefix in [('lan','192.0.2'),('dmz','10.90.0')]:
  reply=json.loads(sh('ip','netns','exec','gfw-'+z,'python3','-c',dhcpclient,('client100' if z=='dmz' else z+'-client'),prefix+'.1',prefix+'.20'));assert reply['lease']==3600
 assert len(api('GET','/services/leases'))==2
 assert len(api('GET','/services/dns-logs'))>=2
 api('POST','/firewall/services-first/confirm')
 print('PASS: DHCP DORA on two interfaces, reservations, per-pool server ID, DNS and lease options; unified observation API',flush=True)

 feedclient=r"""import socket,struct,sys
name,expected=sys.argv[1:];expected=int(expected)
flags=0x100 if expected==3 else 0
q=struct.pack('!HHHHHH',2345,flags,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(q,('192.0.2.1',53));data=s.recv(65535)
assert data[3]&15==expected,data
"""
 def dns_result(name, code):sh('ip','netns','exec','gfw-lan','python3','-c',feedclient,name,str(code))
 feed_cfg=copy.deepcopy(cfg)
 feed_cfg['dns']['security_feed']={'sha256':'b'*64,'values':['blocked.example','home.arpa'],'exceptions':['allowed.blocked.example']}
 dns_result('sub.blocked.example',5)
 apply(feed_cfg,'dns-feed')
 dns_result('sub.blocked.example',3)
 dns_result('child.allowed.blocked.example',5)
 dns_result('notblocked.example',5)
 for transport in ['udp','tcp']:assert 'DNS OK' in sh('ip','netns','exec','gfw-lan','python3','-c',dnsclient,'192.0.2.1',transport)
 assert any(entry['result']=='BLOCKED' for entry in api('GET','/services/dns-logs'))
 api('POST','/firewall/dns-feed/confirm')
 assert api('GET','/services')['security_feed']['sha256']=='b'*64
 apply(cfg,'dns-feed-disable')
 dns_result('sub.blocked.example',5)
 api('POST','/firewall/dns-feed-disable/rollback')
 dns_result('sub.blocked.example',3)
 apply(cfg,'dns-feed-baseline')
 api('POST','/firewall/dns-feed-baseline/confirm')
 print('PASS: live DNS Feed suffix block, exception, authoritative local zone, journal, confirmation and rollback',flush=True)
 # Enable WAN input temporarily to prove the module itself is interface-bound.
 wanrule={'id':'wan-probe','name':'wan-probe','chain':'input','family':'ipv4','source':'','destination':'','protocol':'udp','destination_port':67,'action':'accept','enabled':True,'source_zone':'wan'}
 probe=copy.deepcopy(firewall);probe['rules'].append(wanrule)
 api('POST','/firewall/apply',{'id':'services-isolation','revision':12,'timeout_seconds':120,'config':probe})
 denied=subprocess.run(['ip','netns','exec','gfw-wan','python3','-c',dhcpclient,'wan-client','198.51.100.1','198.51.100.20'],capture_output=True,text=True)
 assert denied.returncode!=0 and 'timed out' in denied.stderr,denied.stderr
 api('POST','/firewall/services-isolation/rollback')
 print('PASS: DHCP does not answer WAN even when firewall input UDP/67 is allowed',flush=True)
 changed_network=copy.deepcopy(network);changed_network['routes']=[{'destination':'10.99.0.0/16','gateway':'10.90.0.2','interface':'dmz.100','metric':100}]
 api('POST','/network/apply',{'id':'services-net-rebind','revision':2,'timeout_seconds':120,'config':changed_network})
 assert json.loads(sh('ip','netns','exec','gfw-dmz','python3','-c',dhcpclient,'client100','10.90.0.1','10.90.0.20'))['ip']=='10.90.0.20'
 api('POST','/firewall/services-net-rebind/rollback')
 assert json.loads(sh('ip','netns','exec','gfw-dmz','python3','-c',dhcpclient,'client100','10.90.0.1','10.90.0.20'))['ip']=='10.90.0.20'
 print('PASS: managed VLAN recreation and rollback rebind DHCP sockets without losing leases',flush=True)

 changed=copy.deepcopy(cfg);changed['dns']['enabled']=False
 apply(changed,'services-crash');p.kill();p.wait(timeout=30);p=start()
 assert api('GET','/services')['runtime']['dns_running'] and len(api('GET','/services/leases'))==2
 assert 'DNS OK' in sh('ip','netns','exec','gfw-lan','python3','-c',dnsclient,'192.0.2.1','udp')
 print('PASS: SIGKILL restores confirmed DNS/DHCP configuration and preserves acknowledged leases',flush=True)
 apply(changed,'services-timer',30)
 end=time.monotonic()+40
 while time.monotonic()<end and 'pending' in api('GET','/services'):time.sleep(.25)
 assert 'pending' not in api('GET','/services') and api('GET','/services')['runtime']['dns_running']
 api('POST','/firewall/services-timer/confirm',expected=409)
 print('PASS: real 30-second service timeout and late confirmation rejection',flush=True)
 print('ALL INTEGRATED SERVICES TESTS PASSED',flush=True)
finally:
 if p is not None and p.poll() is None:p.terminate();p.wait(timeout=30)
