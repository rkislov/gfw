#!/usr/bin/env python3
"""Isolated GFW UDP logging, packet capture and NFQUEUE trials."""
import json, os, pathlib, socket, subprocess, time, urllib.error, urllib.parse, urllib.request
import ssl, sys

if os.environ.get("GFW_QUALIFICATION_LAB") != "1":
    raise SystemExit("Run only inside a fresh isolated Linux lab with GFW_QUALIFICATION_LAB=1.")
phase = sys.argv[1] if len(sys.argv) == 2 else "standard"
if phase not in {"standard", "extended", "immediate", "patched", "soak", "long", "nfqueue", "nfqueue-long"} or len(sys.argv) > 2:
    raise SystemExit("Usage: load.py [standard|extended|immediate|patched|soak|long|nfqueue|nfqueue-long]")
if pathlib.Path('/var/lib/gfw/admin.token').exists():
    raise SystemExit("The load lab requires a fresh GFW data directory.")
state=pathlib.Path('/state')
nfq_long = phase == "nfqueue-long"
nfq_pauses = nfq_long and os.environ.get("GFW_QUALIFICATION_NFQ_PAUSES") == "1"
base_url = 'https://127.0.0.1:8443' if nfq_long else 'http://127.0.0.1:8088'
tls = ssl._create_unverified_context() if nfq_long else None  # Disposable, self-signed VM fixture.

def sh(*args):
    p=subprocess.run(args,text=True,capture_output=True)
    if p.returncode: raise AssertionError((args,p.stderr))
    return p.stdout
def proc(name,args,**kwargs):
    with (state/(name+'.log')).open('w') as f:
        return subprocess.Popen(args,stderr=f,stdout=kwargs.pop('stdout',f),**kwargs)
def wait(fn, seconds=20):
    deadline=time.monotonic()+seconds
    last=None
    while time.monotonic()<deadline:
        try:
            if value:=fn(): return value
        except (OSError, urllib.error.HTTPError) as exc: last=exc
        time.sleep(.2)
    raise AssertionError(('timeout',last))
def emit(category, **data):
    print('RESULT '+json.dumps(dict(category=category,**data)),flush=True)
def ch(query):
    url='http://127.0.0.1:8123/?'+urllib.parse.urlencode({'query':query})
    with urllib.request.urlopen(urllib.request.Request(url,method='POST'),timeout=8) as r: return r.read().decode().strip()
for name, iface, peer, sub in [('src','lan0','src0','192.0.2'),('dst','wan0','dst0','198.51.100')]:
    sh('ip','netns','add',name)
    sh('ip','link','add',iface,'type','veth','peer','name',peer,'netns',name)
    sh('ip','addr','add',sub+'.1/24','dev',iface)
    sh('ip','link','set',iface,'up')
    sh('ip','-n',name,'addr','add',sub+'.2/24','dev',peer)
    sh('ip','-n',name,'link','set',peer,'up')
    sh('ip','-n',name,'link','set','lo','up')
    sh('ip','-n',name,'route','add','default','via',sub+'.1')
sh('ip','link','set','lo','up')
pathlib.Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
for k in ('nf_conntrack_acct','nf_conntrack_events'):
    pathlib.Path('/proc/sys/net/netfilter',k).write_text('1')
tcpdump_args = []
if phase == "immediate":
    wrapper = pathlib.Path('/usr/local/bin/tcpdump-qualification')
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/tcpdump --immediate-mode "$@"\n')
    wrapper.chmod(0o755)
    tcpdump_args = ['-tcpdump', str(wrapper)]
elif phase == "soak":
    wrapper = pathlib.Path('/usr/local/bin/tcpdump-qualification')
    wrapper.write_text("""#!/usr/bin/python3
import os, sys
args = [a for a in sys.argv[1:] if a != '-U' or not os.path.exists('/state/buffered')]
os.execv('/usr/bin/tcpdump', ['tcpdump', *args])
""")
    wrapper.chmod(0o755)
    tcpdump_args = ['-tcpdump', str(wrapper)]
nfq_args = []
native_nfq = os.environ.get("GFW_QUALIFICATION_NFQ_NATIVE") == "1"
if phase == "nfqueue" and not native_nfq:
    pathlib.Path('/nfq-profile').write_text('1 1024')
    for name, program in {
        'suricata': """#!/usr/bin/python3
import os
import pathlib
import sys
args = sys.argv[1:]
if '-q' in args:
    count, pending = map(int, pathlib.Path('/nfq-profile').read_text().split())
    base = int(args[args.index('-q')+1])
    for queue in range(base+1,base+count):
        args.extend(['-q',str(queue)])
    args.extend(['--set', 'max-pending-packets='+str(pending)])
os.execv('/usr/bin/suricata', ['suricata', *args])
""",
        'nft': """#!/usr/bin/python3
import os
import pathlib
import subprocess
import sys
args=sys.argv[1:]
if '-f' not in args:
    os.execv('/usr/sbin/nft', ['nft', *args])
raw=sys.stdin.read()
count,_=map(int,pathlib.Path('/nfq-profile').read_text().split())
if count>1:
    raw=raw.replace('queue num 43013',f'queue to symhash mod {count} offset 43013')
raise SystemExit(subprocess.run(['/usr/sbin/nft',*args],input=raw,text=True).returncode)
""",
    }.items():
        wrapper = pathlib.Path('/usr/local/bin') / (name + '-qualification')
        wrapper.write_text(program)
        wrapper.chmod(0o755)
        nfq_args += ['-' + name, str(wrapper)]
agent=proc('agent',['/usr/sbin/gfw-agent',*tcpdump_args,*nfq_args,'-enable-apply','-enable-traffic','-enable-capture','-enable-ids','-lan-interface','lan0','-management-port','8443','-state-dir','/var/lib/gfw-agent','-socket','/state/agent.sock'])
panel_args = ['-listen','127.0.0.1:8088']
if nfq_long:
    cert, key = state/'lab.crt', state/'lab.key'
    sh('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
       '-subj','/CN=GFW qualification VM','-keyout',str(key),'-out',str(cert))
    panel_args = ['-listen','0.0.0.0:8443','-tls-cert',str(cert),'-tls-key',str(key)]
panel=proc('panel',['/usr/sbin/gfwd',*panel_args,'-data-dir','/var/lib/gfw','-agent-socket','/state/agent.sock'])
# Native payloads carry a sequence and a distinct marker. Separate UDP tuples
# prevent a matching IPS signature from poisoning the benign flow.
sender=r'''
import json, socket, struct, sys, time
host,port,rate,n,unique,mixed,rotate=sys.argv[1:]
port,rate,n,unique,mixed,rotate=map(int,(port,rate,n,unique,mixed,rotate))
good=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
bad=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
bad.bind(('192.0.2.2',42001))
good.bind(('192.0.2.2',42000))
start=time.monotonic()
for i in range(n):
    if i%16==0:
        wait=start+i/rate-time.monotonic()
        if wait>0: time.sleep(wait)
    evil=bool(mixed and i%20==0)
    if rotate and i%1000==0:
        good.close()
        bad.close()
        good=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        bad=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        pair=(i//1000)%rotate
        good.bind(('192.0.2.2',10000+pair*2))
        bad.bind(('192.0.2.2',10001+pair*2))
    s=bad if evil else good
    if unique:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.bind(('192.0.2.2',10000+i))
    s.sendto((b'GFW-BLOCK' if evil else b'GFW-ALLOW')+struct.pack('!I',i)+b'.'*499,(host,port))
    if unique: s.close()
print(json.dumps(dict(sent=n,bad=(n+19)//20 if mixed else 0,elapsed=time.monotonic()-start)))
'''
receiver=r'''
import json, socket, sys, time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2**20)
s.bind((sys.argv[1],int(sys.argv[2])))
s.settimeout(.2)
print('ready',flush=True)
good=bad=0
last=time.monotonic()
while time.monotonic()-last<1:
    try: pkt=s.recv(2048)
    except socket.timeout: continue
    last=time.monotonic()
    if pkt.startswith(b'GFW-BLOCK'): bad+=1
    elif pkt.startswith(b'GFW-ALLOW'): good+=1
print(json.dumps(dict(good_received=good,bad_received=bad)),flush=True)
'''
def send(rate,n,port,unique=0,mixed=0,*,background=False,rotate=0):
    host='192.0.2.1' if unique else '198.51.100.2'
    args = ['ip','netns','exec','src','python3','-c',sender,host,str(port),str(rate),str(n),str(unique),str(mixed),str(rotate)]
    if background:
        return proc('sender',args,stdout=subprocess.PIPE,text=True)
    return json.loads(sh(*args))
def receive(port):
    r=proc('receiver',['ip','netns','exec','dst','python3','-c',receiver,'198.51.100.2',str(port)],stdout=subprocess.PIPE,text=True)
    assert r.stdout.readline().strip()=='ready'
    return r
def result(r):
    stdout,_=r.communicate(timeout=10)
    assert r.returncode==0
    return json.loads(stdout)
def request(path,method='GET',body=None,headers=None):
    req=urllib.request.Request(base_url+'/api/v1'+path,method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json',**(headers or {})})
    try: return urllib.request.urlopen(req,timeout=45,context=tls)
    except urllib.error.HTTPError as e: raise AssertionError((path,e.code,e.read().decode())) from e
def api(path,method='GET',body=None,headers=None):
    with request(path,method,body,headers) as r: return json.load(r),r.headers
def activate(path,config,id):
    _, h=api(path+'/config')
    saved,_=api(path+'/config','PUT',config,{'If-Match':h['ETag']})
    a,_=api(path+'/apply','POST',{'id':id,'revision':saved['revision'],'timeout_seconds':120})
    assert a['status']=='pending',a
    api(path+'/changes/'+id+'/confirm','POST',{})
def stat():
    return api('/traffic/status')[0]['agent']
def capture_state(id):
    return next(s for s in api('/captures')[0]['sessions'] if s['id']==id)
def counters():
    data=json.loads(sh('nft','-j','list','counter','inet','gfw','gfw_traffic_seen'))['nftables']
    return data[-1]['counter']['packets']
def sensor_pid():
    for process in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            if (process/'comm').read_text().strip() == 'Suricata-Main':
                return int(process.name)
        except FileNotFoundError:
            pass
    raise AssertionError('Suricata process not found')

def queue_listener():
    for line in pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines():
        number, listener, *_ = line.split()
        if number == '43013':
            return int(listener)
    return None

def enable_post_ips_counters():
    monitor = '''table inet lab_measure {
  counter clean {}
  counter attack {}
  chain forwarded {
    type filter hook forward priority 30; policy accept;
    udp dport 41001 @th,64,72 0x4746572d414c4c4f57 counter name "clean"
    udp dport 41001 @th,64,72 0x4746572d424c4f434b counter name "attack"
  }
}'''
    subprocess.run(['/usr/sbin/nft','-f','-'],input=monitor,text=True,check=True)
def forwarded():
    data=json.loads(sh('/usr/sbin/nft','-j','list','counters','table','inet','lab_measure'))['nftables']
    return {item['counter']['name']:item['counter']['packets'] for item in data if 'counter' in item}
try:
    wait(lambda:urllib.request.urlopen(base_url+'/healthz',timeout=1,context=tls).status==200)
    token=(pathlib.Path('/var/lib/gfw/admin.token')).read_text().strip()
    wait(lambda:stat()['conntrack'] and stat()['nflog'])
    wait(lambda:ch('SELECT 1')=='1')
    ch('CREATE DATABASE gfw_lab')
    ch("CREATE USER gfw_lab IDENTIFIED WITH sha256_password BY 'fixture-clickhouse-password'")
    ch('GRANT ALL ON gfw_lab.* TO gfw_lab')
    destination={'url':'http://127.0.0.1:8123','database':'gfw_lab','user':'gfw_lab','password':'fixture-clickhouse-password'}
    api('/traffic/config','PUT',destination)
    wait(lambda:api('/traffic/status')[0]['ready'])
    cfg,h=api('/config')
    base=dict(action='accept',enabled=True,protocol='udp',family='ipv4')
    cfg['config']['rules']=[dict(base,id='log-load',name='Load log',chain='input',destination_port=40001),
        dict(base,id='transit-load',name='Load forward',chain='forward',destination_port=41001)]
    fw,_=api('/config','PUT',cfg['config'],{'If-Match':h['ETag']})
    api('/changes/apply','POST',{'id':'qual-fw-01','revision':fw['revision'],'timeout_seconds':120})
    api('/changes/qual-fw-01/confirm','POST',{})
    emit('stand',kernel=sh('uname','-r').strip(),suricata=sh('suricata','-V').strip(),clickhouse=ch('SELECT version()'),
         cpus=os.cpu_count(),memory_kib=int(pathlib.Path('/proc/meminfo').read_text().splitlines()[0].split()[1]),payload_bytes=512)
    def capture_run(backend,rate,n,seconds=20,mixed=0,sequence=False,before_stop=None):
        import struct
        cfg={'interface':'lan0','backend':backend,'direction':'in','family':'ip','protocol':'udp',
            'source':'192.0.2.2','destination':'198.51.100.2','destination_ports':'41001','seconds':seconds,
            'max_packets':0,'max_mib':256,'retention_hours':1}
        session,_=api('/captures','POST',cfg)
        time.sleep(.35)
        r=receive(41001)
        tx=send(rate,n,41001,mixed=mixed)
        rx=result(r)
        if before_stop:
            emit('tcpdump_io',**before_stop())
        api('/captures/'+session['id']+'/stop','POST')
        done=wait(lambda:(x if (x:=capture_state(session['id']))['state']!='running' else None))
        assert done['packets']>0 and not done.get('error'),done
        positions={}
        if sequence:
            seq=set()
            with request('/captures/'+session['id']+'/file') as pcap:
                header=pcap.read(24)
                assert len(header)==24
                while record:=pcap.read(16):
                    _,_,size,_=struct.unpack('<IIII',record)
                    frame=pcap.read(size)
                    assert len(frame)==size and frame[42:51]==b'GFW-ALLOW'
                    seq.add(struct.unpack_from('!I',frame,51)[0])
            assert len(seq)==done['packets']
            positions=dict(missing_head=min(seq),missing_middle=max(seq)-min(seq)+1-len(seq),missing_tail=n-1-max(seq))
        api('/captures/'+session['id'],'DELETE')
        return dict(backend=done['backend'],target_pps=rate,**tx,**rx,captured=done['packets'],dropped=done.get('dropped'),
             pcap_bytes=done['bytes'],state=done['state'],**positions)
    if phase == "standard":
        def count(kind):
            return int(ch(f"SELECT uniqExact(event_id) FROM gfw_lab.gfw_traffic_v1 WHERE kind='{kind}' AND dport=40001"))
        for n,rate in [(1000,1000),(4000,10000),(12000,40000)]:
            offline=n==12000
            if offline:
                api('/traffic/config','PUT',dict(destination,url='http://127.0.0.1:18123'))
                wait(lambda:api('/traffic/status')[0]['error'])
            before=stat(); seen=counters(); rows=count('new'); logs=count('rule')
            # This port is intentionally local. The sink prevents ICMP port-unreachable traffic.
            local=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);local.bind(('192.0.2.1',40001))
            # Use distinct source ranges for the three runs even while older flows remain active.
            original=sender
            sender=original.replace('10000+i',str({1000:10000,4000:12000,12000:18000}[n])+'+i')
            run=send(rate,n,40001,unique=1)
            sender=original
            local.close()
            time.sleep(1)
            queued=stat()['queued']
            if offline:
                assert queued>0,stat()
                api('/traffic/config','PUT',destination)
            drain=time.monotonic()
            wait(lambda:stat()['queued']==0 and api('/traffic/status')[0]['ready'],30)
            after=stat()
            seen_delta=counters()-seen
            delivered=count('new')-rows
            assert seen_delta==n and 0<delivered<=n,(seen_delta,delivered,n)
            events,_=api('/traffic/events?hours=1&rule=log-load')
            assert events and events[0]['rule']=='log-load',events
            emit('logging',**run,target_pps=rate,offline=offline,queued_before_reconnect=queued,drain_seconds=time.monotonic()-drain,
                 new_rows=delivered,rule_rows=count('rule')-logs,nflog_limited=after['rate_limited']-before['rate_limited'],
                 lost=after['lost']-before['lost'],evicted=after['evicted']-before['evicted'],firewall_seen=seen_delta)
        for backend in ['packet','xdp-generic','xdp']:
            for rate in [1000,10000,40000]:
                config={'interface':'lan0','backend':backend,'direction':'in','family':'ip','protocol':'udp',
                    'source':'192.0.2.2','destination':'198.51.100.2','destination_ports':'41001','seconds':12,
                    'max_packets':0,'max_mib':100,'retention_hours':1}
                try:
                    s,_=api('/captures','POST',config)
                except AssertionError as e:
                    emit('capture_unavailable',backend=backend,error=str(e))
                    break
                time.sleep(.35)
                r=receive(41001)
                run=send(rate,rate*2,41001)
                rx=result(r)
                api('/captures/'+s['id']+'/stop','POST')
                done=wait(lambda:(x if (x:=capture_state(s['id']))['state']!='running' else None))
                assert done['state']=='complete' and done['packets']>0,done
                with request('/captures/'+s['id']+'/file',headers={'Range':'bytes=0-39'}) as file:
                    header=file.read()
                    assert file.status==206 and header[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'),header
                emit('capture',backend=done['backend'],target_pps=rate,**run,**rx,captured=done['packets'],
                     dropped=done.get('dropped'),pcap_bytes=done['bytes'],truncated=done['truncated'])
                api('/captures/'+s['id'],'DELETE')
        for mode in ['baseline','closed','open']:
            if mode!='baseline':
                activate('/ids',{'enabled':True,'mode':'ips','failure_policy':mode,'interfaces':['lan0'],
                    'home_net':['192.0.2.0/24'],'rules':'drop udp $HOME_NET any -> any 41001 (msg:"Lab load"; content:"GFW-BLOCK"; depth:9; sid:1000011; rev:1;)'},
                    'qual-ips-'+mode)
                assert api('/ids/state')[0]['ips_hooked']
            for rate in [1000,10000,40000]:
                getq=lambda:api('/ids/state')[0]['runtime'].get('queue') or {}
                before=getq()
                r=receive(41001)
                run=send(rate,rate*2,41001,mixed=1)
                rx=result(r)
                after=getq()
                emit('ips',mode=mode,target_pps=rate,**run,**rx,queue_before=before,queue_after=after)
                if rate==1000 and mode=='closed':
                    assert rx['bad_received']==0 and rx['good_received']>=int((run['sent']-run['bad'])*.95),rx
                    wait(lambda:any(a['sid']==1000011 and a['action']=='blocked' for a in api('/ids/alerts')[0]))
    elif phase == "extended":
        for repeat in range(1,4):
            emit('capture_repeat',repeat=repeat,**capture_run('packet',40000,80000,sequence=True))
        for backend in ['packet','xdp-generic','xdp']:
            emit('capture_peak',**capture_run(backend,100000,200000))
        r=receive(41001)
        emit('ips_peak',mode='baseline',target_pps=100000,**send(100000,200000,41001,mixed=1),**result(r))
        for mode in ['closed','open']:
            activate('/ids',{'enabled':True,'mode':'ips','failure_policy':mode,'interfaces':['lan0'],
                'home_net':['192.0.2.0/24'],'rules':'drop udp $HOME_NET any -> any 41001 (msg:"Lab load"; content:"GFW-BLOCK"; depth:9; sid:1000011; rev:1;)'},
                'qual-ips-'+mode)
            getq=lambda:api('/ids/state')[0]['runtime']['queue']
            if mode=='closed':
                before=getq()
                data=capture_run('xdp',40000,400000,seconds=24,mixed=1)
                emit('combined',mode=mode,**data,queue_before=before,queue_after=getq())
            before=getq()
            r=receive(41001)
            emit('ips_peak',mode=mode,target_pps=100000,**send(100000,200000,41001,mixed=1),**result(r),queue_before=before,queue_after=getq())
            pid=next(int(p.name) for p in pathlib.Path('/proc').glob('[0-9]*') if (p/'comm').exists()
                     and (p/'comm').read_text().strip()=='Suricata-Main')
            import signal
            os.kill(pid,signal.SIGSTOP)
            try:
                r=receive(41001)
                tx=send(40000,16000,41001,mixed=1)
                after=getq()
                rx=result(r)
            finally:
                os.kill(pid,signal.SIGCONT)
            emit('ips_stopped',mode=mode,**tx,**rx,queue_after=after)
            if mode=='closed':
                assert rx['good_received']==rx['bad_received']==0,rx
            else:
                assert rx['good_received']>0 and rx['bad_received']>0,rx
    elif phase == "nfqueue":
        import signal
        queue_file = pathlib.Path('/proc/net/netfilter/nfnetlink_queue')
        enable_post_ips_counters()
        def queues():
            result={}
            for line in queue_file.read_text().splitlines():
                fields=list(map(int,line.split()))
                if 43013 <= fields[0] <= 43016:
                    result[fields[0]]=dict(portid=fields[1],waiting=fields[2],kernel_dropped=fields[5],
                                           user_dropped=fields[6],sequence=fields[7])
            return result
        def apply_profile(name, count, pending, trial):
            if not native_nfq:
                pathlib.Path('/nfq-profile').write_text(f'{count} {pending}')
            activate('/ids',{'enabled':True,'mode':'ips','failure_policy':'closed','interfaces':['lan0'],
                'home_net':['192.0.2.0/24'],
                'rules':f'drop udp $HOME_NET any -> any 41001 (msg:"Lab {name} {trial}"; content:"GFW-BLOCK"; depth:9; sid:1000011; rev:1;)'},f'nfq-trial-{trial:02}')
            assert set(queues())==set(range(43013,43013+count)),queues()
            rules=sh('/usr/sbin/nft','list','table','inet','gfw_ips')
            assert 'bypass' not in rules,rules
            assert ('symhash' in rules)==(count>1),rules
        single_sender=sender
        spread_sender=sender[:sender.index('good=socket.socket')]+r'''
start=time.monotonic()
sockets=[]
for i in range(n):
    if i%16==0:
        delay=start+i/rate-time.monotonic()
        if delay>0: time.sleep(delay)
    if i%16000==0:
        for s in sockets:
            s.close()
        sockets=[]
        for slot in range(64):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.bind(('192.0.2.2',10000+(i//16000%700)*64+slot))
            sockets.append(s)
    evil=bool(i%20==0)
    s=sockets[(i//20%32)*2+evil]
    s.sendto((b'GFW-BLOCK' if evil else b'GFW-ALLOW')+struct.pack('!I',i)+b'.'*499,(host,port))
print(json.dumps(dict(sent=n,bad=(n+19)//20,elapsed=time.monotonic()-start)))
'''
        profiles=[('stock',1,1024),('deeper',1,4096),('parallel',4,1024),('parallel-deeper',4,4096)]
        trials = [(name,count,pending,spread,pause) for spread,pause,order in
                  [(False,0,profiles),(True,0,profiles[::-1]),(False,100,profiles[1:]+profiles[:1])]
                  for name,count,pending in order]
        if native_nfq:
            trials = [('native',1,4096,False,0),('native',1,4096,False,100)]
        for trial, (name,count,pending,spread,pause_ms) in enumerate(trials,1):
            sender=spread_sender if spread else single_sender
            apply_profile(name,count,pending,trial)
            before=queues()
            before_forward=forwarded()
            seen=counters()
            r=receive(41001)
            cfg={'interface':'lan0','backend':'packet','direction':'in','family':'ip','protocol':'udp',
                 'source':'192.0.2.2','destination':'198.51.100.2','destination_ports':'41001','seconds':15,
                 'snaplen':64,'max_packets':0,'max_mib':256,'retention_hours':1}
            session,_=api('/captures','POST',cfg)
            time.sleep(.35)
            tx=send(100000,1200000,41001,mixed=1,background=True,rotate=1200)
            peak={q:0 for q in before}
            pause_at = time.monotonic() + 5
            while tx.poll() is None:
                if pause_ms and time.monotonic() >= pause_at:
                    pid = sensor_pid()
                    os.kill(pid,signal.SIGSTOP)
                    try:
                        time.sleep(pause_ms/1000)
                        for q, stats in queues().items():
                            peak[q]=max(peak[q],stats['waiting'])
                    finally:
                        os.kill(pid,signal.SIGCONT)
                    pause_at = float('inf')
                for q, stats in queues().items():
                    peak[q]=max(peak[q],stats['waiting'])
                time.sleep(.05)
            sent=result(tx)
            rx=result(r)
            after=queues()
            after_forward=forwarded()
            observed=counters()-seen
            verdict={key:after_forward[key]-value for key,value in before_forward.items()}
            assert observed==sent['sent'] and verdict['attack']==rx['bad_received']==0,(observed,verdict,rx,sent)
            delta={q:{key:after[q][key]-before[q][key] for key in ('kernel_dropped','user_dropped','sequence')}
                   for q in before}
            api('/captures/'+session['id']+'/stop','POST')
            capture=wait(lambda:(value if (value:=capture_state(session['id']))['state']!='running' else None))
            api('/captures/'+session['id'],'DELETE')
            emit('nfq_compare',trial=trial,profile=name,queues=count,pending=pending,spread=spread,pause_ms=pause_ms,
                 **sent,**rx,forwarded=verdict,firewall_seen=observed,queue_delta=delta,
                 queue_peak=peak,capture_packets=capture['packets'],capture_dropped=capture.get('dropped'),traffic=stat())
        sender=single_sender
        count = 1 if native_nfq else 4
        apply_profile('native' if native_nfq else 'parallel-deeper',count,4096,99)
        pid=sensor_pid()
        before=forwarded()
        os.kill(pid,signal.SIGSTOP)
        try:
            r=receive(41001)
            sent=send(100000,150000,41001,mixed=1,rotate=150)
            held=queues()
            if native_nfq:
                assert held[43013]['waiting'] == 16384,held
            assert forwarded()==before and sum(q['kernel_dropped']+q['user_dropped'] for q in held.values())>0,held
            rx=result(r)
            assert rx['good_received']==rx['bad_received']==0,rx
            emit('nfq_full_closed',**sent,**rx,queue=held,forwarded_during_stop=0)
        finally:
            os.kill(pid,signal.SIGCONT)
        os.kill(agent.pid,signal.SIGSTOP)
        try:
            os.kill(pid,signal.SIGKILL)
            wait(lambda:not queues(),5)
            before=forwarded()
            r=receive(41001)
            sent=send(100000,100000,41001,mixed=1,rotate=100)
            rx=result(r)
            assert forwarded()==before and rx['good_received']==rx['bad_received']==0,rx
            # Exercise the LAN anti-lockout rule while the IPS listener is absent.
            with socket.socket() as listener:
                listener.bind(('192.0.2.1',8443))
                listener.listen()
                sh('ip','netns','exec','src','python3','-c',
                   'import socket; socket.create_connection(("192.0.2.1", 8443), timeout=2).close()')
            emit('nfq_no_listener_closed',**sent,**rx,lan_management_reachable=True)
        finally:
            os.kill(agent.pid,signal.SIGCONT)
    elif phase in {"soak", "long", "nfqueue-long"}:
        if phase == "soak":
            def packet_writer():
                for child in pathlib.Path('/proc').glob('[0-9]*'):
                    try:
                        if (child/'comm').read_text().strip() == 'tcpdump':
                            io = dict(line.split(': ') for line in (child/'io').read_text().splitlines())
                            return {'writes':int(io['syscw']),'bytes':int(io['wchar'])}
                    except FileNotFoundError:
                        pass
                raise AssertionError("tcpdump process was absent before capture stop")
            for rep in range(1,4):
                for buffered in (False, True):
                    if buffered:
                        (state/'buffered').touch()
                    else:
                        (state/'buffered').unlink(missing_ok=True)
                    trial = capture_run('packet',100000,400000,seconds=15,sequence=True,before_stop=packet_writer)
                    emit('compare',repeat=rep,buffered=buffered,**trial)
                    assert trial['missing_head'] == trial['missing_tail'] == 0,trial
                    assert trial['sent'] - trial['captured'] == trial['dropped'] == trial['missing_middle'],trial
            (state/'buffered').touch()
        activate('/ids',{'enabled':True,'mode':'ips','failure_policy':'closed','interfaces':['lan0'],
            'home_net':['192.0.2.0/24'],'rules':'drop udp $HOME_NET any -> any 41001 (msg:"Lab load"; content:"GFW-BLOCK"; depth:9; sid:1000011; rev:1;)'},
            'soak-ips-closed')
        def db_totals():
            return ch("SELECT kind,uniqExact(event_id) FROM gfw_lab.gfw_traffic_v1 WHERE dport=41001 GROUP BY kind ORDER BY kind")
        def udp_stats():
            lines = sh('ip','netns','exec','dst','cat','/proc/net/snmp').splitlines()
            keys, values = [line.split()[1:] for line in lines if line.startswith('Udp:')]
            return {key:int(value) for key,value in zip(keys,values)}
        def link_stats():
            keys = ('rx_packets','rx_dropped','rx_missed_errors','tx_packets','tx_dropped')
            return {iface:{key:int(pathlib.Path('/sys/class/net',iface,'statistics',key).read_text())
                           for key in keys} for iface in ('lan0','wan0')}
        windows, packets, pairs = (3, 9000000, 9000) if phase == "soak" else (12, 32000000, 18000)
        if nfq_pauses:
            windows, packets, pairs = 7, 18000000, 18000
        duration = packets // 100000
        if nfq_long:
            enable_post_ips_counters()
            before_forward = forwarded()
            release = api('/status')[0]['version']
            listener = queue_listener()
            queue_start = api('/ids/state')[0]['runtime']['queue']
            assert listener is not None and queue_start and queue_start['waiting']==0,queue_start
            assert 'bypass' not in sh('/usr/sbin/nft','list','table','inet','gfw_ips')
            lan_probe = r'''
import json, pathlib, ssl, sys, time, urllib.request
token = pathlib.Path('/var/lib/gfw/admin.token').read_text().strip()
req = urllib.request.Request('https://192.0.2.1:8443/api/v1/auth/me',
                             headers={'Authorization': 'Bearer '+token})
context = ssl._create_unverified_context()
limit = time.monotonic() + int(sys.argv[1])
attempted = passed = 0
errors = []
max_ms = 0
print('ready', flush=True)
while time.monotonic() < limit:
    started = time.monotonic()
    attempted += 1
    try:
        with urllib.request.urlopen(req, timeout=.8, context=context) as response:
            if json.load(response)['role'] != 'admin':
                raise ValueError('unexpected account role')
        passed += 1
        max_ms = max(max_ms, round(1000 * (time.monotonic() - started), 3))
    except (OSError, ValueError) as error:
        if len(errors) < 10:
            errors.append(str(error))
    time.sleep(max(0, 1 - (time.monotonic() - started)))
print(json.dumps(dict(attempted=attempted, passed=passed, max_ms=max_ms, errors=errors)),flush=True)
'''
            lan = proc('lan',['ip','netns','exec','src','python3','-c',lan_probe,str(duration+4)],
                       stdout=subprocess.PIPE,text=True)
            assert lan.stdout.readline().strip()=='ready'
            emit('nfq_long_start',version=release,policy='fail-closed',target_pps=100000,packets=packets,forced_pauses=nfq_pauses)
        before=stat()
        udp_before=udp_stats()
        links_before=link_stats()
        seen=counters()
        r=receive(41001)
        tx=send(100000,packets,41001,mixed=1,background=True,rotate=pairs)
        if nfq_pauses:
            pause_worker = r'''
import json, os, signal, sys, time
pid = int(sys.argv[1])
start = time.monotonic()
pauses = []
for second in range(15, 180, 15):
    time.sleep(max(0, start + second - time.monotonic()))
    before = time.monotonic()
    os.kill(pid, signal.SIGSTOP)
    try:
        time.sleep(.1)
    finally:
        os.kill(pid, signal.SIGCONT)
    pauses.append(round((time.monotonic() - before)*1000, 3))
print(json.dumps({'durations_ms': pauses}))
'''
            pauses = proc('pauses',['python3','-c',pause_worker,str(sensor_pid())],stdout=subprocess.PIPE,text=True)
        for window in range(1,windows+1):
            cfg={'interface':'lan0','backend':'packet','direction':'in','family':'ip','protocol':'udp',
                 'source':'192.0.2.2','destination':'198.51.100.2','destination_ports':'41001','seconds':25,
                 'snaplen':64,'max_packets':0,'max_mib':256,'retention_hours':1}
            s,_=api('/captures','POST',cfg)
            done=wait(lambda:(x if (x:=capture_state(s['id']))['state']!='running' else None),35)
            assert done['packets']>0 and not done.get('error'),done
            emit('soak_capture',window=window,packets=done['packets'],dropped=done.get('dropped'),
                 pcap_bytes=done['bytes'],reason=done['reason'],state=done['state'],
                 queue=api('/ids/state')[0]['runtime']['queue'],traffic=stat())
            api('/captures/'+s['id'],'DELETE')
        stdout,_=tx.communicate(timeout=35)
        assert tx.returncode==0
        sent=json.loads(stdout)
        rx=result(r)
        wait(lambda:stat()['queued']==0,25)
        observed=counters()-seen
        queue=api('/ids/state')[0]['runtime']['queue']
        extras={}
        if nfq_long:
            after_forward=forwarded()
            verdict={key:after_forward[key]-value for key,value in before_forward.items()}
            lan_result=result(lan)
            assert observed==sent['sent'] and verdict['attack']==0, (observed,sent,verdict)
            assert 99000<=sent['sent']/sent['elapsed']<=101000, sent
            assert queue and queue_listener()==listener and queue['waiting']==0,queue
            assert lan_result['attempted']>=duration-10,lan_result
            extras=dict(version=release,forwarded=verdict,queue_start=queue_start,lan=lan_result)
            if nfq_pauses:
                extras['forced_pauses']=result(pauses)['durations_ms']
                assert len(extras['forced_pauses'])==11,extras
        emit('nfq_long' if nfq_long else 'soak',**sent,**rx,firewall_seen=observed,traffic_before=before,traffic_after=stat(),
             queue=queue,clickhouse_counts=db_totals(),udp_before=udp_before,udp_after=udp_stats(),
             links_before=links_before,links_after=link_stats(),**extras)
        assert rx['bad_received']==0
    else:
        for rate, repeats in [(40000,3),(100000,3)]:
            for repeat in range(1,repeats+1):
                data = capture_run('packet', rate, rate * 2, sequence=True)
                emit('capture_' + phase, repeat=repeat, **data)
                if phase == "patched":
                    assert data['sent'] - data['captured'] == data['dropped'], data
    print('PASS load phases completed',flush=True)
except Exception:
    for f in ['agent','panel','clickhouse']:
        p=state/(f+'.log')
        if p.exists(): print(p.read_text()[-3000:],flush=True)
    raise
finally:
    for p in [panel,agent]:
        if p.poll() is None: p.terminate()
