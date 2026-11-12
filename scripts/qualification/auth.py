#!/usr/bin/env python3
"""Isolated GFW OpenLDAP and FreeRADIUS protocol checks."""
import io, zipfile, base64, hashlib, hmac, http.cookiejar, json, os, pathlib, re, signal, socket, struct, subprocess, time, urllib.error, urllib.request
if os.environ.get("GFW_QUALIFICATION_LAB") != "1":
    raise SystemExit("Run only inside a fresh isolated Linux lab with GFW_QUALIFICATION_LAB=1.")
root=pathlib.Path('/state')
password='provider-test-password'
secret='fixture-radius-secret-123456789'
ldap_base='dc=example,dc=test'
bind_dn='cn=reader,'+ldap_base
def sh(*args,stdin=None):
    p=subprocess.run(args,input=stdin,text=True,capture_output=True)
    assert p.returncode==0,(args[0],p.stdout,p.stderr)
    return p.stdout
procs=[]
def start(name,args):
    with (root/(name+'.log')).open('w') as f:
        p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT)
    procs.append(p)
    return p
def wait(f,seconds=12):
    deadline=time.monotonic()+seconds
    error=None
    while time.monotonic()<deadline:
        try:
            if x:=f(): return x
        except OSError as exc: error=exc
        time.sleep(.1)
    raise AssertionError(('timeout',error))
def emit(check,**data):
    print('RESULT '+json.dumps(dict(category='auth',check=check,**data)),flush=True)
def request(method,path,data=None,headers=None,opener=urllib.request,expected=200):
    req=urllib.request.Request('http://127.0.0.1:8088/api/v1'+path,method=method,
        data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json',**(headers or {})})
    try:
        r=opener.urlopen(req,timeout=20) if hasattr(opener,'urlopen') else opener.open(req,timeout=20)
    except urllib.error.HTTPError as e: r=e
    with r:
        raw=r.read()
        assert r.status==expected,(path,r.status,raw.decode(errors='replace'))
        return (json.loads(raw) if r.headers.get_content_type()=='application/json' else raw),r.headers
def admin(method,path,data=None,headers=None):
    return request(method,path,data,{'Authorization':'Bearer '+key,**(headers or {})})
def login(name,passw=password,code='',expected=200):
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    data,_=request('POST','/auth/login',{'username':name,'password':passw,'code':code},opener=opener,expected=expected)
    return opener,data.get('csrf','')
def otp(key,step):
    digest=hmac.new(key,struct.pack('!Q',step),hashlib.sha1).digest()
    return str((struct.unpack_from('!I',digest,digest[-1]&15)[0]&0x7fffffff)%1000000).zfill(6)

try:
    sh('ip','link','set','lo','up')
    sh('ip','link','add','lan0','type','dummy')
    sh('ip','addr','add','192.0.2.1/24','dev','lan0')
    sh('ip','link','set','lan0','up')
    sh('ip','netns','add','vpn')
    sh('ip','link','add','wan0','type','veth','peer','name','wan1','netns','vpn')
    sh('ip','addr','add','198.51.100.1/24','dev','wan0')
    sh('ip','link','set','wan0','up')
    sh('ip','-n','vpn','addr','add','198.51.100.2/24','dev','wan1')
    sh('ip','-n','vpn','link','set','wan1','up')
    sh('ip','-n','vpn','link','set','lo','up')
    sh('ip','netns','add','vpnpeer')
    sh('ip','link','add','peer0','type','veth','peer','name','peer1','netns','vpnpeer')
    sh('ip','addr','add','198.51.101.1/24','dev','peer0')
    sh('ip','link','set','peer0','up')
    sh('ip','-n','vpnpeer','addr','add','198.51.101.2/24','dev','peer1')
    sh('ip','-n','vpnpeer','link','set','peer1','up')
    sh('ip','-n','vpnpeer','link','set','lo','up')
    sh('ip','-n','vpnpeer','route','add','198.51.100.1/32','via','198.51.101.1')
    (root/'db').mkdir()
    sh('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=GFW fixture CA','-keyout','/state/ca.key','-out','/state/ca.pem')
    sh('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=127.0.0.1','-keyout','/state/ldap.key','-out','/state/ldap.csr')
    (root/'ldap.ext').write_text('subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
    sh('openssl','x509','-req','-in','/state/ldap.csr','-CA','/state/ca.pem','-CAkey','/state/ca.key','-CAcreateserial','-extfile','/state/ldap.ext','-days','1','-out','/state/ldap.pem')
    (root/'slapd.conf').write_text(f'''include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile /state/slapd.pid
modulepath /usr/lib/ldap
moduleload back_mdb
TLSCertificateFile /state/ldap.pem
TLSCertificateKeyFile /state/ldap.key
TLSCACertificateFile /state/ca.pem
database mdb
maxsize 1073741824
suffix "{ldap_base}"
rootdn "cn=admin,{ldap_base}"
rootpw fixture-ldap-admin-pass
directory /state/db
access to attrs=userPassword by anonymous auth by self write by * none
access to * by dn.exact="{bind_dn}" read by self read by * none
''')
    sh('slapadd','-f','/state/slapd.conf',stdin=f'''dn: {ldap_base}
objectClass: dcObject
objectClass: organization
o: GFW lab
dc: example

dn: {bind_dn}
objectClass: inetOrgPerson
cn: reader
sn: reader
uid: reader
userPassword: fixture-ldap-reader-pass

dn: uid=ldapuser,{ldap_base}
objectClass: inetOrgPerson
cn: LDAP User
sn: User
uid: ldapuser
userPassword: {password}

dn: uid=unassigned,{ldap_base}
objectClass: inetOrgPerson
cn: Unassigned
sn: User
uid: unassigned
userPassword: {password}
''')
    start('slapd',['slapd','-d','256','-h','ldaps://127.0.0.1:1636','-f','/state/slapd.conf'])
    os.environ['LDAPTLS_CACERT']='/state/ca.pem'
    def ldap_ready():
        return subprocess.run(['ldapwhoami','-x','-H','ldaps://127.0.0.1:1636','-D',bind_dn,
            '-w','fixture-ldap-reader-pass'],capture_output=True).returncode==0
    wait(ldap_ready)
    users=pathlib.Path('/etc/freeradius/3.0/mods-config/files/authorize')
    users.write_text(f'radiuspeer Cleartext-Password := "{password}"\nradiususer Cleartext-Password := "{password}"\nradiustotp Cleartext-Password := "{password}"\n'+users.read_text())
    clients=pathlib.Path('/etc/freeradius/3.0/clients.conf')
    clients.write_text(clients.read_text().replace('testing123',secret))
    radius=start('radius',['freeradius','-X'])
    wait(lambda: 'Ready to process requests' in (root/'radius.log').read_text())
    assert radius.poll() is None
    pathlib.Path('/etc/gfw').mkdir(exist_ok=True)
    (pathlib.Path('/etc/gfw')/'vpn-auth.key').write_text(os.urandom(32).hex())
    pathlib.Path('/run/gfw-auth').mkdir(exist_ok=True)
    start('agent',['/usr/sbin/gfw-agent','-enable-apply','-enable-openvpn','-lan-interface','lan0','-management-port','8443',
        '-socket','/state/agent.sock','-state-dir','/state/agent','-openvpn-runtime','/run/ovpn'] +
        (['-enable-ipsec','-charon','/usr/lib/ipsec/charon','-ipsec-runtime','/run/ike'] if os.environ.get('GFW_IKE_LAB') else []))
    start('panel',['/usr/sbin/gfwd','-listen','127.0.0.1:8088','-data-dir','/state/control','-agent-socket','/state/agent.sock',
        '-vpn-auth-socket','/run/gfw-auth/openvpn.sock','-vpn-auth-key','/etc/gfw/vpn-auth.key'])
    wait(lambda: urllib.request.urlopen('http://127.0.0.1:8088/healthz',timeout=1).status==200)
    key=(root/'control/admin.token').read_text().strip()
    ldap={'url':'ldaps://127.0.0.1:1636','base_dn':ldap_base,'attribute':'uid','bind_dn':bind_dn,
          'bind_password':'fixture-ldap-reader-pass','ca':(root/'ca.pem').read_text()}
    rad={'address':'127.0.0.1:1812','secret':secret}
    admin('PUT','/users/ldap',ldap)
    admin('PUT','/users/radius',rad)
    for name,provider,id in [('ldapuser','ldap','1'*32),('radiususer','radius','2'*32)]:
        admin('PUT','/users',{'name':name,'source':provider,'role':'user','grants':['openvpn:'+id,'ipsec:'+str(int(id[0])+2)*32]})
        client,csrf=login(name)
        me,_=request('GET','/auth/me',opener=client)
        assert me['role']=='user' and me['user']==name and csrf
        request('GET','/users',opener=client,expected=403)
        login(name,'wrong-provider-password',expected=401)
        emit(provider+'-panel',positive=True,bad_password_denied=True,admin_access_denied=True)
    login('unassigned',expected=401)
    admin('PUT','/users/ldap',dict(ldap,ca=''))
    login('ldapuser',expected=401)
    admin('PUT','/users/ldap',dict(ldap,url='ldaps://localhost:1636'))
    login('ldapuser',expected=401)
    admin('PUT','/users/ldap',ldap)
    emit('ldap-negative',unknown_ca_denied=True,wrong_hostname_denied=True,unassigned_denied=True)
    admin('PUT','/users/radius',dict(rad,secret='incorrect-radius-shared-secret'))
    login('radiususer',expected=401)
    admin('PUT','/users/radius',rad)
    emit('radius-negative',wrong_secret_denied=True)
    ca,_=admin('POST','/pki/ca',{'name':'VPN Test','common_name':'VPN Test Root','days':365})
    srv,_=admin('POST','/pki/issue',{'name':'gateway','common_name':'gateway','ca_id':ca['id'],'usage':'server','days':30,'ips':['198.51.100.1']})
    admin('PUT','/users',{'name':'radiuspeer','source':'radius','role':'user','grants':['openvpn:'+'2'*32,'ipsec:'+'4'*32]})
    instances=[]
    for index,provider in enumerate(['ldap','radius'],1):
        name=provider+'user'
        instances.append({'id':str(index)*32,'name':provider,'interface':f'ovpn{index}','mode':'server','enabled':True,
            'certificate_id':srv['id'],'address':f'10.8{index}.0.1/24','bind_address':'198.51.100.1',
            'port':1193+index,'protocol':'udp','clients':[{'username':name,'address':f'10.8{index}.0.2'}],
            'routes':[],'auth':{'password':provider,'certificate':False,'totp':False},'public_endpoint':'198.51.100.1'})
    instances[1]['clients'].append({'username':'radiuspeer','address':'10.82.0.3'})
    _,h=admin('GET','/openvpn/runtime/config')
    draft,_=admin('PUT','/openvpn/runtime/config',{'instances':instances},{'If-Match':h['ETag']})
    admin('POST','/openvpn/runtime/apply',{'id':'auth-real-vpn','revision':draft['revision'],'timeout_seconds':60})
    admin('POST','/openvpn/runtime/changes/auth-real-vpn/confirm',{})
    for index,provider in enumerate(['ldap','radius'],1):
        name=provider+'user'
        client,csrf=login(name)
        profile,_=request('POST','/portal/export',{'id':'openvpn:'+str(index)*32},{'X-GFW-CSRF':csrf},client)
        (root/'client.ovpn').write_bytes(profile)
        (root/'vpn.password').write_text(name+'\n'+password+'\n')
        os.chmod(root/'vpn.password',0o600)
        vpn=start('vpn-'+provider,['ip','netns','exec','vpn','/usr/sbin/openvpn','--config','/state/client.ovpn','--auth-user-pass','/state/vpn.password'])
        wait(lambda:'Initialization Sequence Completed' in (root/('vpn-'+provider+'.log')).read_text(),20)
        assert f'10.8{index}.0.2/24' in sh('ip','-n','vpn','-4','address')
        if provider == 'radius':
            peer, csrf = login('radiuspeer')
            second, _ = request('POST','/portal/export',{'id':'openvpn:'+'2'*32},{'X-GFW-CSRF':csrf},peer)
            (root/'peer.ovpn').write_bytes(second)
            (root/'peer.password').write_text('radiuspeer\n'+password+'\n')
            os.chmod(root/'peer.password',0o600)
            second_vpn = start('vpn-peer',['ip','netns','exec','vpnpeer','/usr/sbin/openvpn','--config','/state/peer.ovpn','--auth-user-pass','/state/peer.password'])
            wait(lambda:'Initialization Sequence Completed' in (root/'vpn-peer.log').read_text(),20)
            def openvpn_sessions():
                state,_ = admin('GET','/openvpn/runtime/state')
                runtime = next(item for item in state['agent']['runtime'] if item['id'] == '2'*32)
                return {item['username']: item['client_id'] for item in runtime['sessions']}
            current = wait(lambda: (found if len(found := openvpn_sessions()) == 2 else None))
            # Keep this client from reconnecting before verifying server-side state.
            vpn.send_signal(signal.SIGSTOP)
            try:
                payload = {'profile_id':'2'*32,'session_id':current['radiususer'],'user':'radiususer'}
                request('POST','/vpn/openvpn/disconnect',dict(payload,user='radiuspeer'),{'Authorization':'Bearer '+key},expected=409)
                admin('POST','/vpn/openvpn/disconnect',payload)
                wait(lambda: openvpn_sessions() == {'radiuspeer':current['radiuspeer']})
                assert second_vpn.poll() is None
            finally:
                vpn.send_signal(signal.SIGCONT)
                second_vpn.terminate()
                second_vpn.wait(timeout=8)
            emit('openvpn-targeted-disconnect',wrong_user_denied=True,peer_session_unchanged=True)
        vpn.terminate()
        vpn.wait(timeout=8)
        emit(provider+'-openvpn',handshake=True,portal_export=True)
    if os.environ.get('GFW_IKE_LAB'):
        sh('ip','addr','add','10.91.0.1/32','dev','lo')
        for index,provider in enumerate(['ldap','radius'],1):
            name=provider+'user'
            tunnel=dict(id=str(index+2)*32,name=provider,interface=f'ikeleft{index}',enabled=True,initiate=False,
                        local_address='198.51.100.1',remote_address='',local_networks=['10.91.0.0/24'],
                        remote_networks=['10.92.0.0/24'],certificate_id=srv['id'],peer_certificate_id='',
                        auth=dict(password=provider,certificate=False,totp=False),public_endpoint='198.51.100.1')
            _,h=admin('GET','/ipsec/config')
            draft,_=admin('PUT','/ipsec/config',{'tunnels':[tunnel]},{'If-Match':h['ETag']})
            tx='auth-real-ike-'+provider
            admin('POST','/ipsec/apply',{'id':tx,'revision':draft['revision'],'timeout_seconds':60})
            admin('POST','/ipsec/changes/'+tx+'/confirm',{})
            client,csrf=login(name)
            archive,_=request('POST','/portal/export',{'id':'ipsec:'+tunnel['id']},{'X-GFW-CSRF':csrf},client)
            destination=root/('ike-'+provider)
            zipfile.ZipFile(io.BytesIO(archive)).extractall(destination)
            config=destination/'swanctl.conf'
            config.write_text(config.read_text().replace('REPLACE_WITH_PASSWORD',password))
            (root/'client.vici').unlink(missing_ok=True)
            strong=root/'strongswan.conf'
            strong.write_text("""charon {
 load_modular = no
 load = random nonce sha1 sha2 hmac kdf pem x509 revocation constraints pkcs1 pkcs8 pubkey openssl kernel-netlink socket-default vici eap-identity eap-gtc
 plugins {
  vici {
   socket = unix:///state/client.vici
  }
 }
}
""")
            ike=start('ike-'+provider,['ip','netns','exec','vpn','unshare','-m','sh','-ec',
                'mount --make-rprivate /; mount -t tmpfs tmpfs /run; exec env STRONGSWAN_CONF=/state/strongswan.conf /usr/lib/ipsec/charon'])
            try:
                wait(lambda:(root/'client.vici').exists() and ike.poll() is None)
                cmd=['ip','netns','exec','vpn','/usr/sbin/swanctl']
                sh(*cmd,'--load-all','--uri','unix:///state/client.vici','--file',str(config))
                out=sh(*cmd,'--initiate','--uri','unix:///state/client.vici','--child','gfw','--timeout','8')
                assert 'CHILD_SA' in out and 'established' in out
                emit(provider+'-ikev2',handshake=True,portal_export=True)
                if provider == 'radius':
                    peer, csrf = login('radiuspeer')
                    second,_ = request('POST','/portal/export',{'id':'ipsec:'+tunnel['id']},{'X-GFW-CSRF':csrf},peer)
                    peer_dir = root/'ike-peer'
                    zipfile.ZipFile(io.BytesIO(second)).extractall(peer_dir)
                    config2 = peer_dir/'swanctl.conf'
                    config2.write_text(config2.read_text().replace('REPLACE_WITH_PASSWORD',password))
                    peer_conf = root/'strongswan-peer.conf'
                    peer_conf.write_text(strong.read_text().replace('client.vici','peer.vici'))
                    ike2=start('ike-peer',['ip','netns','exec','vpnpeer','unshare','-m','sh','-ec',
                        'mount --make-rprivate /; mount -t tmpfs tmpfs /run; exec env STRONGSWAN_CONF=/state/strongswan-peer.conf /usr/lib/ipsec/charon'])
                    try:
                        wait(lambda:(root/'peer.vici').exists() and ike2.poll() is None)
                        peer_cmd=['ip','netns','exec','vpnpeer','/usr/sbin/swanctl']
                        sh(*peer_cmd,'--load-all','--uri','unix:///state/peer.vici','--file',str(config2))
                        peer_out=sh(*peer_cmd,'--initiate','--uri','unix:///state/peer.vici','--child','gfw','--timeout','8')
                        assert 'CHILD_SA' in peer_out and 'established' in peer_out
                        def ipsec_sessions():
                            state,_ = admin('GET','/ipsec/state')
                            runtime = next(item for item in state['agent']['runtime'] if item['id'] == tunnel['id'])
                            return {item.get('username',item['identity']): item['ike_id'] for item in runtime.get('sessions',[])}
                        current = wait(lambda: (found if len(found := ipsec_sessions()) == 2 else None))
                        payload = {'profile_id':tunnel['id'],'session_id':current['radiususer'],'user':'radiususer'}
                        request('POST','/vpn/ipsec/disconnect',dict(payload,user='radiuspeer'),{'Authorization':'Bearer '+key},expected=409)
                        admin('POST','/vpn/ipsec/disconnect',payload)
                        wait(lambda: ipsec_sessions() == {'radiuspeer':current['radiuspeer']})
                        assert ike2.poll() is None
                        events,_ = admin('GET','/audit')
                        assert any('vpn.disconnect.ipsec.success:' in e['action'] and e['actor']=='admin' for e in events)
                        emit('ipsec-targeted-disconnect',wrong_user_denied=True,peer_sa_unchanged=True,audited=True)
                    finally:
                        ike2.terminate()
                        ike2.wait(timeout=10)
            finally:
                ike.terminate()
                ike.wait(timeout=10)
    admin('PUT','/users',{'name':'radiustotp','source':'radius','role':'user','grants':[]})
    client,csrf=login('radiustotp')
    enrollment,_=request('POST','/portal/totp/begin',{'password':password},{'X-GFW-CSRF':csrf},client)
    encoded=enrollment['secret']
    totpkey=base64.b32decode(encoded+'='*(-len(encoded)%8))
    step=int(time.time())//30
    request('POST','/portal/totp/confirm',{'code':otp(totpkey,step)},{'X-GFW-CSRF':csrf},client)
    login('radiustotp',expected=401)
    next_code=otp(totpkey,step+1)
    login('radiustotp',code=next_code)
    login('radiustotp',code=next_code,expected=401)
    emit('radius-totp',missing_denied=True,valid_accepted=True,replay_denied=True)
except Exception:
    # Suppress logs of test services that may echo test credentials.
    for name in ['agent','panel','vpn-ldap','vpn-radius','ike-ldap','ike-radius']:
        p=root/(name+'.log')
        if p.exists(): print(p.read_text()[-2400:],flush=True)
    raise
finally:
    for p in reversed(procs):
        if p.poll() is None: p.terminate()
