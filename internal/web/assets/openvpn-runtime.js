'use strict';
let ovpnRuntimeSnapshot=null,ovpnRuntimeState=null,ovpnRuntimeClients=[],ovpnRuntimeDirty=false,ovpnRuntimePolling=false;
function ovpnRuntimeMode(){const f=$('ovpn-runtime-form'),server=f.elements.mode.value==='server';$('ovpn-runtime-server').hidden=!server;$('ovpn-runtime-client').hidden=server;f.elements.bind_address.required=server;f.elements.remote.required=!server;f.elements.server_certificate_id.required=!server;ovpnRuntimeCertificateOptions();}
function ovpnRuntimeCertificateOptions(){
 const f=$('ovpn-runtime-form'),role=f.elements.mode.value==='server'?'server':'client';
 for(const[name,usage]of [['certificate_id',role],['server_certificate_id','server'],['add_client_certificate','client']]){const el=f.elements[name],old=el.value;el.replaceChildren();const empty=node('option','Выберите сертификат');empty.value='';el.append(empty);for(const c of ovpnCertificates.filter(c=>c.kind==='local'&&c.usage===usage&&(name!=='add_client_certificate'||!c.revoked_at&&Date.parse(c.not_after)>Date.now()))){const o=node('option',c.name+(c.revoked_at?' · отозван':Date.parse(c.not_after)<=Date.now()?' · истёк':''));o.value=c.id;el.append(o);}if([...el.options].some(x=>x.value===old))el.value=old;}
}
function ovpnRuntimeButtons(){
 const s=ovpnRuntimeState?.agent,p=s?.pending;
 $('ovpn-runtime-apply').disabled=ovpnBusy||ovpnRuntimeDirty||!s?.enabled||!!p;
 $('ovpn-runtime-confirm').disabled=ovpnBusy||p?.kind!=='openvpn'||p.status!=='pending'||Date.parse(p.deadline)<=Date.now();
 $('ovpn-runtime-rollback').disabled=ovpnBusy||p?.kind!=='openvpn';
 $('ovpn-runtime-plan').disabled=ovpnBusy||ovpnRuntimeDirty;
 $('ovpn-crl-sync').disabled=ovpnBusy||!s?.enabled;
}
function ovpnRuntimeMark(){ovpnRuntimeDirty=true;$('ovpn-runtime-dirty').textContent='Есть изменения в форме. Сохраните экземпляр или очистите форму перед применением.';ovpnRuntimeButtons();}
function ovpnRuntimeReset(){const f=$('ovpn-runtime-form');f.reset();f.elements.id.value='';ovpnRuntimeClients=[];ovpnRuntimeDirty=false;$('ovpn-runtime-dirty').textContent='Применяется только сохранённая конфигурация.';ovpnRuntimeMode();ovpnRuntimeRenderClients();ovpnRuntimeButtons();}
function ovpnRuntimeRenderClients(){const list=$('ovpn-runtime-clients');list.replaceChildren();for(const [index,p]of ovpnRuntimeClients.entries()){const row=node('div','','mt-2 flex gap-4 text-sm');row.append(node('span',`${[p.username, ovpnCertificates.find(c=>c.id===p.certificate_id)?.name || p.certificate_id, p.address].filter(Boolean).join(' · ')}`),ovpnAction('Убрать',()=>{ovpnRuntimeClients.splice(index,1);ovpnRuntimeMark();ovpnRuntimeRenderClients();}));list.append(row);}}
function ovpnRuntimeInstance(){const f=new FormData($('ovpn-runtime-form')),mode=f.get('mode'),auth=vpnMethod($('ovpn-runtime-form'));return{id:f.get('id')||ovpnID(),name:f.get('name').trim(),interface:f.get('interface').trim(),mode,auth:mode==='server'&&(auth.password||auth.totp||!auth.certificate)?auth:undefined,public_endpoint:mode==='server'?f.get('public_endpoint').trim():'',client_routes:mode==='server'?ovpnSplit(f.get('client_routes')):[],enabled:f.has('enabled'),certificate_id:f.get('certificate_id'),server_certificate_id:mode==='client'?f.get('server_certificate_id'):'',address:f.get('address').trim(),bind_address:mode==='server'?f.get('bind_address').trim():'',remote:mode==='client'?f.get('remote').trim():'',port:Number(f.get('port')),protocol:f.get('protocol'),routes:mode==='client'?ovpnSplit(f.get('routes')):[],clients:mode==='server'?structuredClone(ovpnRuntimeClients):[]};}
async function ovpnRuntimeSave(config){ovpnRuntimeSnapshot=await api('/openvpn/runtime/config',{method:'PUT',headers:{'If-Match':JSON.stringify(String(ovpnRuntimeSnapshot.revision))},body:JSON.stringify(config)});ovpnRuntimeRender();await ovpnRuntimePoll();}
function ovpnRuntimeRender(){
 $('ovpn-runtime-instances').replaceChildren();
 for(const i of ovpnRuntimeSnapshot?.config.instances||[]){const r=ovpnRuntimeState?.agent.runtime?.find(x=>x.id===i.id),row=node('div','','py-4');row.append(node('p',`${i.name} · ${i.mode==='server'?'Сервер':'Клиент'} · ${i.interface}`,'font-medium'),node('p',`${i.enabled?'Включён':'Выключен'} · ${i.address} · ${i.protocol.toUpperCase()} ${i.mode==='server'?i.bind_address:i.remote}:${i.port}`,'mt-1 text-sm text-slate-600'),node('p',r?.blocked?`Заблокирован: ${r.blocked}`:r?.ready?`Работает · CRL №${r.crl_number}`:r?.running?'Процесс запущен, подключение не готово':'Процесс остановлен','mt-2 text-sm '+(r?.ready?'text-teal-800':'text-amber-800')));
 if(r?.state)row.append(node('pre',r.state,'mt-2 whitespace-pre-wrap break-all text-xs text-slate-500'));
 const actions=node('div','','mt-3 flex flex-wrap gap-4');actions.append(ovpnAction('Изменить',()=>{const f=$('ovpn-runtime-form');f.reset();f.elements.mode.value=i.mode;setVPNMethod(f,i.auth);ovpnRuntimeMode();for(const[k,v]of Object.entries(i)){const el=f.elements[k];if(!el)continue;if(el.type==='checkbox')el.checked=v;else el.value=Array.isArray(v)?v.join('\n'):v;}ovpnRuntimeClients=structuredClone(i.clients||[]);ovpnRuntimeRenderClients();ovpnRuntimeMark();f.elements.name.focus();}),ovpnAction('Удалить из черновика',async()=>{const c=structuredClone(ovpnRuntimeSnapshot.config);c.instances=c.instances.filter(x=>x.id!==i.id);await ovpnRuntimeSave(c);message('Экземпляр удалён из черновика. Для остановки примените конфигурацию.');}),ovpnAction('Журнал',async()=>{const lines=await api('/openvpn/runtime/logs/'+encodeURIComponent(i.id));$('ovpn-runtime-logs').textContent=lines.join('\n')||'Журнал пока пуст.';$('ovpn-runtime-logs').hidden=false;}));row.append(actions);$('ovpn-runtime-instances').append(row);
 }
 if(!ovpnRuntimeSnapshot?.config.instances?.length)$('ovpn-runtime-instances').append(node('p','Экземпляров пока нет. Добавьте сервер или клиент ниже.','py-3 text-sm text-slate-500'));ovpnRuntimeButtons();
 const sessions = $('ovpn-runtime-sessions');
 sessions.replaceChildren();
 for (const instance of ovpnRuntimeState?.agent.active?.instances || []) {
   if (instance.mode !== 'server') continue;
   const runtime = ovpnRuntimeState.agent.runtime?.find(item => item.id === instance.id);
   for (const client of runtime?.sessions || []) {
     if (typeof client !== 'object') continue;
     const user = client.username || client.name;
     const row = node('div', '', 'flex flex-wrap items-center justify-between gap-3 py-2');
     row.append(node('span', `${user} · ${instance.name} · ${client.address} · ${client.remote} · RX ${client.rx_bytes} / TX ${client.tx_bytes}`, 'break-all text-sm'));
     if (Number.isInteger(client.client_id) && user && !runtime.sessions_error) {
       row.append(vpnDisconnectButton('openvpn', instance.id, client.client_id, user, ovpnRuntimePoll));
     }
     sessions.append(row);
   }
 }
 if (!sessions.children.length) sessions.append(node('p', 'Нет активных клиентских подключений.', 'py-2 text-sm text-slate-500'));
}
async function ovpnRuntimePoll(){
 if(!isAdmin()||$('app').hidden||ovpnRuntimePolling)return;ovpnRuntimePolling=true;try{ovpnRuntimeState=await api('/openvpn/runtime/state');const s=ovpnRuntimeState.agent,p=s.pending,crl=ovpnRuntimeState.crl_sync;$('ovpn-runtime-status').textContent=s.enabled?`Подтверждённая ревизия: ${s.confirmed_revision||'ещё нет'}.${s.runtime_error?' Ошибка: '+s.runtime_error:''}`:s.runtime_error||'Применение отключено. Нужен Linux-агент с -enable-openvpn.';$('ovpn-runtime-crl-status').textContent=crl.error?`Доставка CRL ожидает повтора: ${crl.error}`:crl.last_success&&!crl.last_success.startsWith('0001')?`CRL синхронизирован: ${new Date(crl.last_success).toLocaleString()}`:'CRL будет синхронизирован после подключения агента.';$('ovpn-runtime-pending').hidden=!p;$('ovpn-runtime-pending-label').textContent=p?`${p.kind==='openvpn'?'Изменение OpenVPN':'Ожидает другое изменение: '+p.kind} · ${p.status}${p.error?' · '+p.error:''}`:'';ovpnRuntimeCount();ovpnRuntimeRender();}catch(e){$('ovpn-runtime-status').textContent=e.message;}finally{ovpnRuntimePolling=false;ovpnRuntimeButtons();}
}
function ovpnRuntimeCount(){const p=ovpnRuntimeState?.agent.pending;if(p)$('ovpn-runtime-timer').textContent=`До автоматического отката: ${Math.max(0,Math.ceil((Date.parse(p.deadline)-Date.now())/1000))} сек.`;ovpnRuntimeButtons();}
async function refreshOpenVPNRuntime(){if(!ovpnRuntimeDirty)ovpnRuntimeSnapshot=await api('/openvpn/runtime/config');ovpnRuntimeCertificateOptions();ovpnRuntimeRender();await ovpnRuntimePoll();}
$('ovpn-runtime-form').addEventListener('input',ovpnRuntimeMark);$('ovpn-runtime-form').elements.mode.addEventListener('change',ovpnRuntimeMode);
$('ovpn-runtime-add-client').addEventListener('click', () => {
  const form = $('ovpn-runtime-form');
  const auth = vpnMethod(form);
  const username = form.elements.add_client_username.value.trim();
  const certificate_id = auth.certificate ? form.elements.add_client_certificate.value : '';
  const address = form.elements.add_client_address.value.trim();
  if (!address || auth.certificate && !certificate_id || (auth.password || auth.totp) && !username) {
    message('Укажите адрес VPN и данные, требуемые выбранным методом входа.');
    return;
  }
  ovpnRuntimeClients.push({username, certificate_id, address});
  for (const field of ['add_client_username', 'add_client_certificate', 'add_client_address']) form.elements[field].value = '';
  ovpnRuntimeMark();
  ovpnRuntimeRenderClients();
});
$('ovpn-runtime-form').addEventListener('submit',e=>{e.preventDefault();const instance=ovpnRuntimeInstance();ovpnRun(async()=>{const config=structuredClone(ovpnRuntimeSnapshot.config),index=config.instances.findIndex(x=>x.id===instance.id);if(index<0)config.instances.push(instance);else config.instances[index]=instance;await ovpnRuntimeSave(config);ovpnRuntimeReset();message('Черновик OpenVPN сохранён. Проверьте план и примените с подтверждением.');});});
$('ovpn-runtime-reset').addEventListener('click',ovpnRuntimeReset);
$('ovpn-runtime-plan').addEventListener('click',()=>ovpnRun(async()=>{const p=await api('/openvpn/runtime/plan',{method:'POST',body:JSON.stringify(ovpnRuntimeSnapshot.config)});$('ovpn-runtime-preview').textContent=[...p.actions,...p.warnings].join('\n');$('ovpn-runtime-preview').hidden=false;}));
$('ovpn-runtime-apply').addEventListener('click',()=>{const timeout=Number($('ovpn-runtime-timeout').value);if(!Number.isInteger(timeout)||timeout<30||timeout>600){message('Срок подтверждения: 30–600 секунд.');return;}ovpnRun(async()=>{try{await api('/openvpn/runtime/apply',{method:'POST',body:JSON.stringify({id:crypto.randomUUID(),revision:ovpnRuntimeSnapshot.revision,timeout_seconds:timeout})});message('OpenVPN применён временно. Проверьте LAN и туннели, затем подтвердите.');}finally{await ovpnRuntimePoll();await pollChanges();}});});
for(const[id,action]of [['ovpn-runtime-confirm','confirm'],['ovpn-runtime-rollback','rollback']])$(id).addEventListener('click',()=>ovpnRun(async()=>{const p=ovpnRuntimeState?.agent.pending;if(p?.kind!=='openvpn')return;try{await api(`/openvpn/runtime/changes/${encodeURIComponent(p.id)}/${action}`,{method:'POST',body:'{}'});message(action==='confirm'?'OpenVPN подтверждён.':'Предыдущие настройки OpenVPN восстановлены. Отзывы сертификатов сохранены.');}finally{await ovpnRuntimePoll();await pollChanges();}}));
$('ovpn-crl-sync').addEventListener('click',()=>ovpnRun(async()=>{await api('/openvpn/runtime/crl-sync',{method:'POST',body:'{}'});await ovpnRuntimePoll();message('CRL доставлен управляемому OpenVPN.');}));
function resetOpenVPNRuntime(){ovpnRuntimeSnapshot=null;ovpnRuntimeState=null;ovpnRuntimeReset();$('ovpn-runtime-logs').hidden=true;}
setInterval(()=>{if(!ovpnBusy)ovpnRuntimePoll();},5000);setInterval(ovpnRuntimeCount,1000);
ovpnRuntimeMode();
