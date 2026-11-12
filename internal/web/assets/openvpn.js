'use strict';
let ovpnSnapshot=null,ovpnState=null,ovpnBusy=false,ovpnCertificates=[];
const ovpnID=()=>crypto.randomUUID().replaceAll('-','');
const ovpnSplit=s=>String(s||'').split(/[\s,]+/).filter(Boolean);
function ovpnControls(){
 for(const el of $('page-openvpn').querySelectorAll('button,input,select,textarea'))el.disabled=ovpnBusy;
 if(typeof ovpnRuntimeButtons==='function')ovpnRuntimeButtons();
 for(const el of $('ovpn-profiles').querySelectorAll('[data-export]'))el.disabled=ovpnBusy||!$('ovpn-secret-consent').checked||el.dataset.export!=='ready';
}
function ovpnAction(text,fn){const b=node('button',text,'text-sm text-teal-800 disabled:opacity-40');b.type='button';b.addEventListener('click',()=>ovpnRun(fn));return b;}
async function ovpnRun(fn){if(ovpnBusy)return;ovpnBusy=true;ovpnControls();try{await fn();}catch(e){message(e.message);}finally{ovpnBusy=false;ovpnControls();}}
function ovpnCertificateOptions(){
 const f=$('ovpn-form');
 for(const[name,usage]of [['server_certificate_id','server'],['client_certificate_id','client']]){
  const el=f.elements[name],selected=el.value;el.replaceChildren();const empty=node('option','Выберите сертификат');empty.value='';el.append(empty);
  for(const c of ovpnCertificates.filter(c=>c.kind==='local'&&c.usage===usage&&!c.revoked_at&&Date.parse(c.not_after)>Date.now())){const option=node('option',`${c.name} · CA ${c.ca_id.slice(0,8)} · до ${new Date(c.not_after).toLocaleDateString()}`);option.value=c.id;el.append(option);}
  if([...el.options].some(o=>o.value===selected))el.value=selected;
 }
}
function ovpnFormProfile(){
 const f=new FormData($('ovpn-form'));
 return{id:f.get('id')||ovpnID(),name:f.get('name').trim(),server_certificate_id:f.get('server_certificate_id'),client_certificate_id:f.get('client_certificate_id'),remote:f.get('remote').trim().toLowerCase(),port:Number(f.get('port')),protocol:f.get('protocol'),routes:ovpnSplit(f.get('routes')),dns:ovpnSplit(f.get('dns'))};
}
function ovpnRender(){
 $('ovpn-profiles').replaceChildren();
 for(const p of ovpnSnapshot?.config.profiles||[]){
  const status=ovpnState?.profiles.find(s=>s.id===p.id),row=node('div','','py-4');
  row.append(node('p',p.name,'font-medium'),node('p',`${p.protocol.toUpperCase()} · ${p.remote}:${p.port}`,'mt-1 text-sm font-mono text-slate-600'));
  if(status?.identity)row.append(node('p',`Сервер: ${status.identity.server_common_name} · клиент: ${status.identity.client_common_name}`,'mt-2 text-xs text-slate-500'),node('p',`SHA256 сервера: ${status.identity.server_fingerprint}`,'mt-1 break-all text-xs font-mono text-slate-500'));
  row.append(node('p',status?.can_export?'Сертификаты проверены. Можно скачать профиль.':status?.error||'Проверка сертификатов недоступна.','mt-2 text-sm '+(status?.can_export?'text-teal-800':'text-red-700')));
  const actions=node('div','','mt-3 flex flex-wrap gap-4');
  actions.append(ovpnAction('Изменить',()=>{const form=$('ovpn-form');for(const[k,v]of Object.entries(p)){if(form.elements[k])form.elements[k].value=Array.isArray(v)?v.join('\n'):v;}$('ovpn-preview').hidden=true;form.elements.name.focus();}),ovpnAction('Удалить',async()=>{const next=structuredClone(ovpnSnapshot.config);next.profiles=next.profiles.filter(x=>x.id!==p.id);await ovpnSave(next);message('Профиль удалён. Ранее выданный файл остаётся действующим до отзыва на сервере.');}));
  const download=ovpnAction('Скачать .ovpn',()=>ovpnDownload(p.id));download.dataset.export=status?.can_export?'ready':'blocked';actions.append(download);row.append(actions);$('ovpn-profiles').append(row);
 }
 if(!ovpnSnapshot?.config.profiles.length)$('ovpn-profiles').append(node('p','Сохранённых профилей пока нет. Выпустите серверный и клиентский сертификаты в разделе CA / ACME.','py-4 text-sm text-slate-500'));
 ovpnControls();
}
async function refreshOpenVPN(){
 const [snap,state,certs]=await Promise.all([api('/openvpn/config'),api('/openvpn/state'),api('/pki')]);
 if($('app').hidden)return;
 ovpnSnapshot=snap;ovpnState=state;ovpnCertificates=certs.certificates;ovpnCertificateOptions();ovpnRender();if(typeof refreshOpenVPNRuntime==='function')await refreshOpenVPNRuntime();
 $('ovpn-revision').textContent=`Ревизия профилей: ${snap.revision}. Клиентские файлы выдаются отдельно от применения экземпляров.`;
}
async function ovpnSave(config){
 const result=await api('/openvpn/config',{method:'PUT',headers:{'If-Match':JSON.stringify(String(ovpnSnapshot.revision))},body:JSON.stringify(config)});
 ovpnSnapshot=result;await refreshOpenVPN();
}
$('ovpn-form').addEventListener('submit',e=>{e.preventDefault();const p=ovpnFormProfile();ovpnRun(async()=>{if(!ovpnSnapshot)throw new Error('Сначала обновите данные.');const next=structuredClone(ovpnSnapshot.config),i=next.profiles.findIndex(x=>x.id===p.id);if(i<0)next.profiles.push(p);else next.profiles[i]=p;await ovpnSave(next);ovpnResetForm();$('ovpn-preview').hidden=true;message('Профиль OpenVPN сохранён. Сетевые настройки устройства не менялись.');});});
$('ovpn-check').addEventListener('click',()=>{if(!$('ovpn-form').reportValidity())return;const profile=ovpnFormProfile();ovpnRun(async()=>{const p=await api('/openvpn/check',{method:'POST',body:JSON.stringify(profile)});$('ovpn-preview').textContent=[`CA: ${p.identity.ca_id}`,`Сервер: ${p.identity.server_common_name}`,`Клиент: ${p.identity.client_common_name}`,`SHA256 сервера: ${p.identity.server_fingerprint}`,...p.warnings].join('\n');$('ovpn-preview').hidden=false;});});
$('ovpn-reset').addEventListener('click',()=>{ovpnResetForm();$('ovpn-preview').hidden=true;});
$('ovpn-refresh').addEventListener('click',()=>ovpnRun(refreshOpenVPN));
$('ovpn-secret-consent').addEventListener('change',ovpnControls);
$('ovpn-form').addEventListener('input',()=>$('ovpn-preview').hidden=true);
async function ovpnDownload(id){
 if(!$('ovpn-secret-consent').checked)throw new Error('Подтвердите, что файл содержит закрытый ключ клиента.');
 const response=await fetch('/api/v1/openvpn/export',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-GFW-CSRF':csrf},body:JSON.stringify({id,revision:ovpnSnapshot.revision})});
 if(!response.ok){if(response.status===401){$('app').hidden=true;$('login').hidden=false;}const e=await response.json();throw new Error(e.error||'Не удалось скачать профиль');}
 const url=URL.createObjectURL(await response.blob()),a=document.createElement('a');a.href=url;a.download='gfw-openvpn.ovpn';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);$('ovpn-secret-consent').checked=false;
 message('Файл .ovpn скачан. Он содержит закрытый ключ клиента: передавайте и храните его как секрет.');
}
function ovpnResetForm(){$('ovpn-form').reset();$('ovpn-form').elements.id.value='';}
function resetOpenVPN(){if(typeof resetOpenVPNRuntime==='function')resetOpenVPNRuntime();ovpnSnapshot=null;ovpnState=null;ovpnCertificates=[];ovpnBusy=false;ovpnResetForm();$('ovpn-profiles').replaceChildren();$('ovpn-preview').hidden=true;$('ovpn-secret-consent').checked=false;}
