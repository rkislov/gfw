#!/usr/bin/env python3
"""Stateful/object/NAT packet tests in disposable network namespaces only."""
import copy
import json
from pathlib import Path
import runpy
import subprocess

lab = runpy.run_path('/work/scripts/agent-lab.py')
sh, api, start, probe = [lab[x] for x in ('sh', 'api', 'start', 'probe')]
lab['peer']('dmz', '203.0.113', '2001:db8:3')
Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
for zone, gateway4, gateway6 in [('lan','192.0.2.1','2001:db8:1::1'),('wan','198.51.100.1','2001:db8:2::1'),('dmz','203.0.113.1','2001:db8:3::1')]:
    sh('ip','-n','gfw-'+zone,'route','add','default','via',gateway4)
    sh('ip','-n','gfw-'+zone,'-6','route','add','default','via',gateway6)
sh('ip','addr','add','198.51.100.9/24','dev','wan0')
server_code = '''from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,socket,sys,socketserver
class Handler(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def do_GET(self):
  data=json.dumps({'peer':self.client_address[0],'path':self.path}).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
class Server(ThreadingHTTPServer):
 address_family=socket.AF_INET6 if sys.argv[1]=='6' else socket.AF_INET
 def server_bind(self):
  if self.address_family==socket.AF_INET6:self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  socketserver.TCPServer.server_bind(self)
  self.server_name="lab";self.server_port=8080
Server(('::' if sys.argv[1]=='6' else '0.0.0.0',8080),Handler).serve_forever()
'''
servers=[subprocess.Popen(['ip','netns','exec','gfw-'+zone,'python3','-c',server_code,family],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE) for zone,family in [('wan','4'),('dmz','4'),('lan','4'),('wan','6')]]

# Wait for each server to bind; spawning Python is asynchronous.
for zone,family in [('wan','4'),('dmz','4'),('lan','4'),('wan','6')]:
    ready="""import socket,time,sys
family=socket.AF_INET6 if sys.argv[1]=='6' else socket.AF_INET
for _ in range(100):
 try:
  s=socket.socket(family);s.settimeout(.1);s.connect(('::1' if family==socket.AF_INET6 else '127.0.0.1',8080));s.close();break
 except OSError:time.sleep(.05)
else:raise RuntimeError('HTTP server not ready')
"""
    sh('ip','netns','exec','gfw-'+zone,'python3','-c',ready,family)

def request(zone,url,ok=True):
    r=subprocess.run(['ip','netns','exec','gfw-'+zone,'curl','-g','--noproxy','*','--max-time','3','-fsS',url],capture_output=True,text=True)
    assert (r.returncode==0)==ok,(zone,url,r.returncode,r.stderr)
    return json.loads(r.stdout) if ok else None

def rule(id,source='',destination='',**kwargs):
    r={'id':id,'name':id,'chain':'forward','family':'ipv4','source':'','destination':'','protocol':'any','destination_port':0,'action':'accept','enabled':True,'source_zone':source,'destination_zone':destination};r.update(kwargs);return r

def nat(id,kind,inzone='lan',outzone='wan',**kwargs):
    n={'id':id,'name':id,'type':kind,'enabled':True,'source_zone':inzone,'destination_zone':outzone,'source':'192.0.2.0/24' if kind!='dnat' else '', 'destination':'','protocol':'any','destination_port':0,'translated_address':'','translated_port':0,'allow_forward':False,'hairpin':False};n.update(kwargs);return n

c={'stateful':True,'default_input':'drop','default_forward':'drop',
   'zones':[{'id':z,'name':z.upper(),'kind':z,'interfaces':[z+'0']} for z in ['lan','wan','dmz']],
   'address_groups':[{'id':'clients4','name':'LAN clients','family':'ipv4','networks':['192.0.2.0/24','192.0.2.2/32']},{'id':'wanhost','name':'WAN host','family':'ipv4','networks':['198.51.100.2/32']}],
   'service_groups':[{'id':'web','name':'Web','protocol':'tcp','ports':['8080','8080-8080']},{'id':'both','name':'TCP UDP','protocol':'tcp_udp','ports':['9090','9091-9093']}],
   'rules':[rule('lan-web','lan','wan',source_group='clients4',destination_group='wanhost',service='web'),rule('wan-nd','wan',chain='input',family='ipv6',protocol='icmpv6'),rule('lan-v6-web','lan','wan',family='ipv6',protocol='tcp',destination_port=8080),rule('both-protocols','lan','wan',service='both')],
   'nat':[nat('outbound','masquerade')]}
p=None;client=None
try:
    p=start()
    revision=100
    def apply(config,id):
        global revision
        revision+=1
        r=api('POST','/apply',{'id':id,'revision':revision,'timeout_seconds':120,'config':config})
        assert r['status']=='pending'
        return r
    apply(c,'adv-masq')
    result=request('lan','http://198.51.100.2:8080/');assert result['peer']=='198.51.100.1',(result,sh('nft','list','table','inet','gfw'))
    request('wan','http://192.0.2.2:8080/',False)
    assert request('lan','http://[2001:db8:2::2]:8080/')['peer']=='2001:db8:1::2'
    api('POST','/adv-masq/confirm')
    print('PASS: nft sets/ranges, zone filtering, IPv4 masquerade, IPv6 stateful reply, unsolicited WAN denied',flush=True)

    servers.append(subprocess.Popen(['python3','-m','http.server','8443','--bind','192.0.2.1'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
    with_feed=copy.deepcopy(c)
    with_feed['security_feed']={'sha256':'a'*64,
      'values':['192.0.2.0/24','198.51.100.2/32','198.51.100.0/24','2001:db8:2::/64'],
      'exceptions':['192.0.2.2/32','198.51.100.2/32']}
    plan=api('POST','/plan',with_feed)
    assert 'gfw:feed:ip6:daddr' in plan['nftables']
    apply(with_feed,'feed-ip-allow')
    assert request('lan','http://198.51.100.2:8080/')['peer']=='198.51.100.1'
    request('lan','http://[2001:db8:2::2]:8080/',False)
    probe('gfw-lan','http://192.0.2.1:8443/',True)
    api('POST','/feed-ip-allow/confirm')
    assert api('GET','')['security_feed']['sha256']=='a'*64

    no_exception=copy.deepcopy(with_feed)
    no_exception['security_feed']['exceptions']=[]
    apply(no_exception,'feed-ip-deny')
    request('lan','http://198.51.100.2:8080/',False)
    assert 'gfw:feed:ip:saddr' in sh('nft','list','table','inet','gfw')
    probe('gfw-lan','http://192.0.2.1:8443/',True)
    api('POST','/feed-ip-deny/rollback')
    assert request('lan','http://198.51.100.2:8080/')['peer']=='198.51.100.1'
    apply(c,'feed-ip-disable')
    assert request('lan','http://[2001:db8:2::2]:8080/')['peer']=='2001:db8:1::2'
    api('POST','/feed-ip-disable/confirm')
    assert 'security_feed' not in api('GET','')
    print('PASS: live Feed IPv4/IPv6 block, overlap, exceptions, LAN anti-lockout, confirmation and rollback',flush=True)

    snat=copy.deepcopy(c);snat['nat'][0]=nat('outbound','snat',translated_address='198.51.100.9')
    apply(snat,'adv-snat');assert request('lan','http://198.51.100.2:8080/')['peer']=='198.51.100.9';api('POST','/adv-snat/rollback')
    exempt=copy.deepcopy(c);exempt['nat'].insert(0,nat('exemption','no_snat',destination='198.51.100.2/32'))
    apply(exempt,'adv-exemption');assert request('lan','http://198.51.100.2:8080/')['peer']=='192.0.2.2';api('POST','/adv-exemption/rollback')
    print('PASS: fixed SNAT address and ordered no-SNAT exception',flush=True)

    forwarded=copy.deepcopy(c)
    forwarded['nat'].append(nat('published','dnat','wan','dmz',destination='198.51.100.1/32',protocol='tcp',destination_port=8088,translated_address='203.0.113.2',translated_port=8080,allow_forward=True))
    forwarded['nat'].append(nat('loopback-publish','dnat','wan','lan',destination='198.51.100.1/32',protocol='tcp',destination_port=8089,translated_address='192.0.2.2',translated_port=8080,allow_forward=True,hairpin=True))
    apply(forwarded,'adv-dnat')
    assert request('wan','http://198.51.100.1:8088/')['peer']=='198.51.100.2'
    request('wan','http://203.0.113.2:8080/',False)
    assert request('lan','http://198.51.100.1:8089/')['peer']=='192.0.2.1'
    request('wan','http://198.51.100.1:8443/',False)
    api('POST','/adv-dnat/confirm')
    print('PASS: DNAT + exact forward authorization; direct WAN bypass denied; hairpin DNAT/SNAT works',flush=True)

    invalid=copy.deepcopy(forwarded);invalid['nat'][-1]['destination_port']=8443
    api('POST','/plan',invalid,expected=422)
    invalid=copy.deepcopy(c);invalid['address_groups']=invalid['address_groups'][1:]
    api('POST','/plan',invalid,expected=422)
    invalid=copy.deepcopy(c);invalid['zones'][1]['interfaces'].append('lan0')
    api('POST','/plan',invalid,expected=422)
    print('PASS: NAT cannot hijack LAN management port; referenced object deletion and duplicate zone interface rejected',flush=True)

    client_code="""import http.client,json,sys
c=http.client.HTTPConnection('198.51.100.2',8080,timeout=2)
for line in sys.stdin:
 try:
  c.request('GET','/persistent');r=c.getresponse();r.read();print('ok',flush=True)
 except Exception:
  print('blocked',flush=True)
"""
    client=subprocess.Popen(['ip','netns','exec','gfw-lan','python3','-c',client_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    client.stdin.write('GET\n');client.stdin.flush();assert client.stdout.readline().strip()=='ok'
    denied=copy.deepcopy(forwarded);denied['rules']=[r for r in denied['rules'] if r['id']!='lan-web']
    apply(denied,'adv-revoke')
    client.stdin.write('GET\n');client.stdin.flush();assert client.stdout.readline().strip()=='blocked'
    api('POST','/adv-revoke/rollback')
    assert request('lan','http://198.51.100.2:8080/')['peer']=='198.51.100.1'
    print('PASS: changing policy revokes existing allowed TCP flow; rollback restores new connections',flush=True)
    print('ALL ADVANCED FIREWALL TESTS PASSED',flush=True)
finally:
    if client is not None:
        client.terminate();client.wait(timeout=5)
    if p is not None and p.poll() is None:
        p.terminate();p.wait(timeout=30)
    for server in servers:
        server.terminate();server.wait(timeout=5)

