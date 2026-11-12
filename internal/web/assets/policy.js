'use strict';
function policyConfig(){if(!snapshot)return null;const c=snapshot.config;for(const k of ['zones','address_groups','service_groups','nat'])c[k]??=[];return c;}
function objectName(list,id){return id?(list.find(x=>x.id===id)?.name||id):'Любая';}
function policyRuleAddresses(r){const c=policyConfig();const src=r.source_group?objectName(c.address_groups,r.source_group):(r.source||'Любой');const dst=r.destination_group?objectName(c.address_groups,r.destination_group):(r.destination||'Любой');return `${r.source_zone?objectName(c.zones,r.source_zone)+': ':''}${src} → ${r.destination_zone?objectName(c.zones,r.destination_zone)+': ':''}${dst}`;}
function policyRuleService(r){const c=policyConfig();return r.service?objectName(c.service_groups,r.service):`${r.protocol.toUpperCase()}${r.destination_port?':'+r.destination_port:''}`;}
function splitValues(s){return String(s||'').split(/[\s,]+/).filter(Boolean);}
function updateSelect(el,values,empty){const selected=el.value;el.replaceChildren();const option=node('option',empty);option.value='';el.append(option);for(const x of values){const o=node('option',x.name);o.value=x.id;el.append(o);}el.value=values.some(x=>x.id===selected)?selected:'';}
function policyUses(id){const c=policyConfig(),names=[];for(const r of c.rules){if([r.source_zone,r.destination_zone,r.source_group,r.destination_group,r.service].includes(id))names.push(r.name);}for(const n of c.nat){if([n.source_zone,n.destination_zone].includes(id))names.push('NAT: '+n.name);}return names;}
function editForm(id,object){const f=$(id);for(const[k,v]of Object.entries(object)){const input=f.elements[k];if(!input)continue;if(input.type==='checkbox')input.checked=v;else input.value=Array.isArray(v)?v.join(', '):v;}f.elements.name.focus();}
function policyRows(target,items,describe,form,collection){
 $(target).replaceChildren();for(const o of items){const row=node('div','','flex flex-wrap justify-between items-center gap-3 py-4');const info=node('div','');info.append(node('p',o.name,'font-medium text-sm'),node('p',describe(o),'mt-1 text-xs text-slate-500'));const actions=node('div','','flex gap-4');const edit=node('button','Изменить','text-xs text-teal-800');edit.addEventListener('click',()=>editForm(form,o));const del=node('button','Удалить','text-xs text-slate-500');del.addEventListener('click',()=>{const used=policyUses(o.id);if(used.length){message('Объект используется: '+used.join(', '));return;}const c=policyConfig();c[collection]=c[collection].filter(x=>x.id!==o.id);markDirty();renderRules();});actions.append(edit,del);row.append(info,actions);$(target).append(row);}if(!items.length)$(target).append(node('p','Объекты не добавлены.','py-4 text-sm text-slate-500'));
}
function renderPolicyObjects(){
 const c=policyConfig();if(!c)return;$('stateful').checked=!!c.stateful;
 policyRows('zones-list',c.zones,z=>`${z.kind.toUpperCase()} · ${z.interfaces?.join(', ')||'интерфейсы не назначены'}`,'zone-form','zones');
 policyRows('address-list',c.address_groups,g=>`${g.family.toUpperCase()} · ${g.networks.join(', ')}`,'address-form','address_groups');
 policyRows('service-list',c.service_groups,g=>`${g.protocol==='tcp_udp'?'TCP и UDP':g.protocol.toUpperCase()} · ${g.ports.join(', ')}`,'service-form','service_groups');
 for(const el of document.querySelectorAll('[data-policy-zone]'))updateSelect(el,c.zones,el.required?'Выберите зону':'Любая зона');
 for(const el of document.querySelectorAll('[data-policy-address]'))updateSelect(el,c.address_groups,'Прямой IP/CIDR или любой');
 for(const el of document.querySelectorAll('[data-policy-service]'))updateSelect(el,c.service_groups,'Задать протокол и порт вручную');
 renderNAT();syncRuleForm();
}
function syncRuleForm(){
 const f=$('rule-form');if(!f.elements.service)return;
 for(const [group,direct]of [['source_group','source'],['destination_group','destination']]){f.elements[direct].disabled=!!f.elements[group].value;if(f.elements[group].value)f.elements[direct].value='';}
 const service=!!f.elements.service.value;f.elements.protocol.disabled=service;f.elements.destination_port.disabled=service;if(service){f.elements.protocol.value='any';f.elements.destination_port.value='';}
 f.elements.destination_zone.disabled=f.elements.chain.value==='input';if(f.elements.destination_zone.disabled)f.elements.destination_zone.value='';
 f.elements.source_zone.disabled=f.elements.chain.value==='output';if(f.elements.source_zone.disabled)f.elements.source_zone.value='';
 const transport = service ? policyConfig()?.service_groups.find(group => group.id === f.elements.service.value)?.protocol : f.elements.protocol.value;
 const allowed = f.elements.chain.value === 'forward' && f.elements.action.value === 'accept' && ['tcp','udp','tcp_udp'].includes(transport);
 const fast = f.elements.flow_policy.querySelector('option[value="fast"]');
 fast.disabled = !allowed;
 if (!allowed && f.elements.flow_policy.value === 'fast') f.elements.flow_policy.value = 'normal';
}
for(const name of ['service','source_group','destination_group','chain','protocol','action'])$('rule-form').elements[name].addEventListener('change',syncRuleForm);
function editPolicyRule(r){const f=$('rule-form');f.reset();for(const[k,v]of Object.entries(r)){if(f.elements[k])f.elements[k].value=v;}f.elements.flow_policy.value=r.fast_path?'fast':r.log_required?'required':'normal';syncRuleForm();f.elements.name.focus();}
$('stateful').addEventListener('change',()=>{const c=policyConfig();if(c){c.stateful=$('stateful').checked;markDirty();}});
$('zone-presets').addEventListener('click',()=>{const c=policyConfig();if(!c)return;for(const kind of ['lan','wan','dmz','vpn'])if(!c.zones.some(x=>x.kind===kind))c.zones.push({id:crypto.randomUUID(),name:kind.toUpperCase(),kind,interfaces:[]});markDirty();renderRules();});
function savePolicyObject(form,collection,build){$(form).addEventListener('submit',e=>{e.preventDefault();const c=policyConfig();if(!c)return;const f=new FormData(e.target),o=build(f);o.id=f.get('id')||crypto.randomUUID();o.name=f.get('name').trim();const i=c[collection].findIndex(x=>x.id===o.id);if(i<0)c[collection].push(o);else c[collection][i]=o;e.target.reset();if(form==='nat-form')syncNATForm();markDirty();renderRules();});}
savePolicyObject('zone-form','zones',f=>({kind:f.get('kind'),interfaces:splitValues(f.get('interfaces'))}));
savePolicyObject('address-form','address_groups',f=>({family:f.get('family'),networks:splitValues(f.get('networks'))}));
savePolicyObject('service-form','service_groups',f=>({protocol:f.get('protocol'),ports:splitValues(f.get('ports'))}));
savePolicyObject('nat-form','nat',f=>{
 const type=f.get('type'),dnat=type==='dnat';
 return{type,enabled:f.has('enabled'),source_zone:f.get('source_zone'),destination_zone:f.get('destination_zone'),source:f.get('source').trim(),destination:f.get('destination').trim(),protocol:f.get('protocol'),destination_port:Number(f.get('destination_port')||0),translated_address:['dnat','snat'].includes(type)?f.get('translated_address').trim():'',translated_port:dnat?Number(f.get('translated_port')||0):0,allow_forward:dnat&&f.has('allow_forward'),hairpin:dnat&&f.has('hairpin')};
});
const natNames={masquerade:'Выход через интерфейс',snat:'Фиксированный SNAT',no_snat:'Без исходящего NAT',dnat:'Проброс порта'};
function renderNAT(){const c=policyConfig();$('nat-list').replaceChildren();c.nat.forEach((n,i)=>{
 const row=node('div','','flex flex-wrap items-center justify-between gap-3 py-4');const info=node('div','');info.append(node('p',n.name+(n.enabled?'':' · выключено'),'font-medium text-sm'),node('p',`${natNames[n.type]} · ${objectName(c.zones,n.source_zone)} → ${objectName(c.zones,n.destination_zone)}${n.type==='dnat'?` · ${n.protocol.toUpperCase()} ${n.destination||'любой IP'}:${n.destination_port} → ${n.translated_address}:${n.translated_port}`:''}${n.type==='snat'?' · '+n.translated_address:''}`,'mt-1 text-xs text-slate-500'));
 if(n.allow_forward)info.append(node('p','Разрешение перенаправленного трафика: включено'+(n.hairpin?' · hairpin включён':''),'mt-2 text-xs text-teal-800'));
 const actions=node('div','','flex flex-wrap gap-3');for(const[label,fn,disabled]of [
 ['Изменить',()=>{editForm('nat-form',n);syncNATForm();},false],
 [n.enabled?'Выключить':'Включить',()=>{n.enabled=!n.enabled;markDirty();renderRules();},false],
 ['↑',()=>{[c.nat[i-1],c.nat[i]]=[c.nat[i],c.nat[i-1]];markDirty();renderRules();},i===0],
 ['↓',()=>{[c.nat[i+1],c.nat[i]]=[c.nat[i],c.nat[i+1]];markDirty();renderRules();},i===c.nat.length-1],
 ['Удалить',()=>{c.nat.splice(i,1);markDirty();renderRules();},false]
 ]){const button=node('button',label,'text-xs text-slate-500 disabled:opacity-30');button.disabled=disabled;button.addEventListener('click',fn);actions.append(button);}row.append(info,actions);$('nat-list').append(row);
 });if(!c.nat.length)$('nat-list').append(node('p','Преобразования не добавлены.','py-4 text-sm text-slate-500'));
}
function syncNATForm(){const f=$('nat-form'),dnat=f.elements.type.value==='dnat',snat=f.elements.type.value==='snat';for(const k of ['translated_port','allow_forward','hairpin'])f.elements[k].disabled=!dnat;f.elements.translated_address.disabled=!dnat&&!snat;if(dnat&&f.elements.protocol.value==='any')f.elements.protocol.value='tcp';}
$('nat-form').elements.type.addEventListener('change',syncNATForm);
$('nat-reset').addEventListener('click',()=>{$('nat-form').reset();syncNATForm();});
syncNATForm();
