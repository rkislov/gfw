#!/usr/bin/env python3
"""Isolated GFW UDP logging, packet capture and NFQUEUE trials."""
import json, os, pathlib, socket, subprocess, time, urllib.error, urllib.parse, urllib.request
import sys

if os.environ.get("GFW_QUALIFICATION_LAB") != "1":
    raise SystemExit("Run only inside a fresh isolated Linux lab with GFW_QUALIFICATION_LAB=1.")
phase = sys.argv[1] if len(sys.argv) == 2 else "standard"
if phase not in {"standard", "extended", "immediate", "patched", "soak", "long"} or len(sys.argv) > 2:
    raise SystemExit("Usage: load.py [standard|extended|immediate|patched|soak|long]")
if pathlib.Path('/var/lib/gfw/admin.token').exists():
    raise SystemExit("The load lab requires a fresh GFW data directory.")
state=pathlib.Path('/state')
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
agent=proc('agent',['/usr/sbin/gfw-agent',*tcpdump_args,'-enable-apply','-enable-traffic','-enable-capture','-enable-ids','-lan-interface','lan0','-management-port','8443','-state-dir','/var/lib/gfw-agent','-socket','/state/agent.sock'])
panel=proc('panel',['/usr/sbin/gfwd','-listen','127.0.0.1:8088','-data-dir','/var/lib/gfw','-agent-socket','/state/agent.sock'])
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
    req=urllib.request.Request('http://127.0.0.1:8088/api/v1'+path,method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json',**(headers or {})})
    try: return urllib.request.urlopen(req,timeout=45)
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
try:
    wait(lambda:urllib.request.urlopen('http://127.0.0.1:8088/healthz',timeout=1).status==200)
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
    elif phase in {"soak", "long"}:
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
        before=stat()
        udp_before=udp_stats()
        links_before=link_stats()
        seen=counters()
        r=receive(41001)
        windows, packets, pairs = (3, 9000000, 9000) if phase == "soak" else (12, 32000000, 18000)
        tx=send(100000,packets,41001,mixed=1,background=True,rotate=pairs)
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
        emit('soak',**sent,**rx,firewall_seen=counters()-seen,traffic_before=before,traffic_after=stat(),
             queue=api('/ids/state')[0]['runtime']['queue'],clickhouse_counts=db_totals(),
             udp_before=udp_before,udp_after=udp_stats(),links_before=links_before,links_after=link_stats())
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
