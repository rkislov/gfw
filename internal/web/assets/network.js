'use strict';
let networkSnapshot = null, networkDirty = false, networkState = null, networkBusy = false, networkEdit = 0;
const linkTypes = {physical:'Ethernet', vlan:'VLAN', bridge:'Мост', bond:'Агрегация'};
function networkMarkDirty() { networkDirty = true; networkEdit++; $('network-dirty').textContent = 'Есть несохранённые изменения сети'; $('network-preview').hidden = true; networkButtons(); }
function networkButtons() {
  $('network-apply').disabled = networkBusy || networkDirty || !networkState?.enabled || !!networkState?.pending;
  $('network-confirm').disabled = networkBusy || networkState?.pending?.kind !== 'network' || networkState?.pending?.status !== 'pending';
  $('network-rollback').disabled = networkBusy || networkState?.pending?.kind !== 'network';
}
function networkCount() {
  const p = networkState?.pending; if (!p) return;
  const seconds = Math.max(0, Math.ceil((Date.parse(p.deadline)-Date.now())/1000));
  $('network-countdown').textContent = p.status === 'pending' ? `До автоматического отката: ${seconds} сек.` : (changeLabels[p.status] || p.status);
  if (seconds === 0) $('network-confirm').disabled = true;
}
async function networkPoll() {
  if (!isAdmin() || $('app').hidden) return;
  try {
    networkState = await api('/network/state'); const s = networkState;
    $('network-state').textContent = s.enabled ? `${s.backend === "netplan" ? "Netplan" : "etcnet"} · подтверждённая ревизия: ${s.confirmed_revision || 'ещё нет'}. Изменения ожидают подтверждения 30–600 секунд.` : 'Сетевое применение на агенте отключено. Доступны инвентаризация и черновик.';
    $('network-lan').textContent = s.enabled ? `Защищённый LAN: ${s.lan_interface}. Его нельзя удалить, выключить или включить в другой мост. ${s.backend === "netplan" ? "LAN и его зависимости ведёт исходный профиль Ubuntu." : "Существующий IP LAN должен сохраниться."}` : '';
    $('network-pending').hidden = !s.pending;
    const own = s.pending?.kind === 'network';
    $('network-confirm').hidden = !own; $('network-rollback').hidden = !own;
    if (s.pending) $('network-pending-text').textContent = `${own ? 'Изменение сети' : (s.pending.kind === 'wireguard' ? 'Изменение VPN — откройте WireGuard' : s.pending.kind === 'services' ? 'Изменение DNS/DHCP — откройте раздел сервисов' : 'Изменение firewall — откройте межсетевой экран')}: ${changeLabels[s.pending.status] || s.pending.status} · ревизия ${s.pending.revision}${s.pending.error ? ' · '+s.pending.error : ''}`;
    $('network-history').replaceChildren(...s.history.filter(r => r.kind === 'network').slice(-5).reverse().map(r => node('p', `${changeLabels[r.status] || r.status} · ревизия ${r.revision}${r.error ? ' · '+r.error : ''}`)));
  } catch (err) { networkState = null; $('network-state').textContent = err.message + '. Таймер незавершённого изменения продолжает работать в агенте.'; }
  networkButtons(); networkCount();
}
async function refreshNetwork() {
  if (!networkDirty) { networkSnapshot = await api('/network/config'); networkRender(); }
  await networkPoll();
}
function networkRender() {
  if (!networkSnapshot) return;
  $('network-links').replaceChildren();
  for (const l of networkSnapshot.config.interfaces) {
    const row = node('div','','flex flex-wrap items-center justify-between gap-4 p-4');
    const details = `${l.name} · ${linkTypes[l.type]} · ${l.up ? 'включён' : 'выключен'} · MTU ${l.mtu}${l.parent ? ` · ${l.parent} / VLAN ${l.vlan}` : ''}${l.members.length ? ' · порты: '+l.members.join(', ') : ''}`;
    const info=node('div','');info.append(node('p',details,'text-sm font-medium'),node('p',l.addresses.join(', ') || 'Без IP-адресов','mt-1 text-xs text-slate-500'));
    const actions=node('div','','flex gap-4');
    const edit=node('button','Изменить','text-sm text-teal-800');edit.addEventListener('click',()=>{
      const f=$('network-link-form');for (const k of ['name','type','parent','mtu','bond_mode']) f.elements[k].value=l[k];f.elements.bond_mode.value=l.bond_mode||'active-backup';f.elements.vlan.value=l.vlan||'';f.elements.up.value=l.up?'yes':'no';f.elements.addresses.value=l.addresses.join('\n');f.elements.members.value=l.members.join(', ');f.elements.adopt.checked=l.adopt;f.elements.name.focus();
    });
    const del=node('button','Удалить из черновика','text-xs text-slate-500');del.addEventListener('click',()=>{networkSnapshot.config.interfaces=networkSnapshot.config.interfaces.filter(x=>x.name!==l.name);networkMarkDirty();networkRender();});
    actions.append(edit,del);row.append(info,actions);$('network-links').append(row);
  }
  if (!networkSnapshot.config.interfaces.length) $('network-links').append(node('p','Управляемые интерфейсы пока не добавлены.','p-5 text-sm text-slate-500'));
  $('network-routes').replaceChildren();networkSnapshot.config.routes.forEach((r,i)=>{
    const row=node('div','','flex flex-wrap items-center justify-between gap-3 p-4 text-sm');row.append(node('span',`${r.destination} → ${r.gateway || 'напрямую'} · ${r.interface} · метрика ${r.metric}`));const del=node('button','Удалить','text-xs text-slate-500');del.addEventListener('click',()=>{networkSnapshot.config.routes.splice(i,1);networkMarkDirty();networkRender();});row.append(del);$('network-routes').append(row);
  });if(!networkSnapshot.config.routes.length)$('network-routes').append(node('p','Статические маршруты не добавлены.','p-5 text-sm text-slate-500'));
}
$('network-link-form').addEventListener('submit',e=>{
  e.preventDefault();if(!networkSnapshot)return;
  const f=new FormData(e.target),type=f.get('type');
  const l={name:f.get('name').trim(),type,parent:type==='vlan'?f.get('parent').trim():'',vlan:type==='vlan'?Number(f.get('vlan')):0,members:['bridge','bond'].includes(type)?f.get('members').split(/[\s,]+/).filter(Boolean):[],bond_mode:type==='bond'?f.get('bond_mode'):'',mtu:Number(f.get('mtu')),up:f.get('up')==='yes',addresses:f.get('addresses').split(/[\s,]+/).filter(Boolean),adopt:f.has('adopt')};
  const i=networkSnapshot.config.interfaces.findIndex(x=>x.name===l.name);if(i<0)networkSnapshot.config.interfaces.push(l);else networkSnapshot.config.interfaces[i]=l;networkMarkDirty();networkRender();e.target.reset();
});
$('network-link-reset').addEventListener('click',()=>$('network-link-form').reset());
$('network-route-form').addEventListener('submit',e=>{e.preventDefault();if(!networkSnapshot)return;const f=new FormData(e.target);networkSnapshot.config.routes.push({destination:f.get('destination').trim(),gateway:f.get('gateway').trim(),interface:f.get('interface').trim(),metric:Number(f.get('metric'))});networkMarkDirty();networkRender();e.target.reset();});
$('network-save').addEventListener('click',async()=>{
  if(!networkSnapshot||networkBusy)return;networkBusy=true;networkButtons();
  const controls=[...$('page-network').querySelectorAll('button,input,select,textarea')].map(el=>[el,el.disabled]);for(const [el]of controls)el.disabled=true;
  try{networkSnapshot=await api('/network/config',{method:'PUT',headers:{'If-Match':JSON.stringify(String(networkSnapshot.revision))},body:JSON.stringify(networkSnapshot.config)});networkDirty=false;$('network-dirty').textContent='Нет несохранённых изменений';networkRender();message('Черновик сети сохранён. Для изменения Linux выполните проверку и применение.');}
  catch(err){message(err.message);}
  finally{for(const[el,disabled]of controls)if(el.isConnected)el.disabled=disabled;networkBusy=false;networkButtons();}
});
$('network-plan').addEventListener('click',async()=>{if(!networkSnapshot)return;const version=networkEdit;try{const p=await api('/network/plan',{method:'POST',body:JSON.stringify(networkSnapshot.config)});if(version!==networkEdit)return;let text=[...p.warnings,...p.actions].join('\n');if(p.protected.length)text+='\n\nЗащищены: '+p.protected.join(', ');for(const[name,files]of Object.entries(p.files)){for(const[file,body]of Object.entries(files))text+=`\n\n${p.backend === "netplan" ? name : "/etc/net/ifaces/" + name}/${file}\n${body}`;}$('network-preview-text').textContent=text;$('network-preview').hidden=false;}catch(err){message(err.message);}});
$('network-apply').addEventListener('click',async()=>{
  const timeout=Number($('network-timeout').value);if(!Number.isInteger(timeout)||timeout<30||timeout>600){message('Срок подтверждения должен быть 30–600 секунд.');return;}if(networkDirty||!networkSnapshot)return;networkBusy=true;networkButtons();
  try{await api('/network/apply',{method:'POST',body:JSON.stringify({id:crypto.randomUUID(),revision:networkSnapshot.revision,timeout_seconds:timeout})});message('Сеть применена временно. Проверьте доступ к панели и подтвердите изменение.');}catch(err){message(err.message);}finally{networkBusy=false;await networkPoll();await pollChanges();}
});
for(const[id,action]of [['network-confirm','confirm'],['network-rollback','rollback']])$(id).addEventListener('click',async()=>{
  const p=networkState?.pending;if(p?.kind!=='network')return;networkBusy=true;networkButtons();try{await api(`/network/changes/${encodeURIComponent(p.id)}/${action}`,{method:'POST',body:'{}'});message(action==='confirm'?'Сеть подтверждена и сохранена.':'Предыдущая сеть и конфигурация восстановлены.');}catch(err){message(err.message);}finally{networkBusy=false;await networkPoll();await pollChanges();}
});
setInterval(()=>{if(!networkBusy)networkPoll();},3000);setInterval(networkCount,1000);

function resetNetwork() { networkSnapshot = null; networkDirty = false; networkState = null; networkBusy = false; $('network-dirty').textContent = 'Нет несохранённых изменений'; }
