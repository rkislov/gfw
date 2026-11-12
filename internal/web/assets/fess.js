'use strict';

const fessForm = $('fess-form');
let fessDraft, fessState, fessBusy, fessDirty, fessGeneration = 0, fessPacks = [];

function fessButtons() {
  const selected = $('fess-site').value !== '';
  for (const id of ['fess-save', 'fess-plan', 'fess-apply', 'fess-delete', 'fess-import', 'fess-confirm', 'fess-rollback', 'fess-catalog']) {
    $(id).disabled = fessBusy || !fessDraft;
  }
  $('fess-delete').disabled ||= !selected;
  $('fess-import').disabled ||= !selected || fessDirty || $('fess-feed-pack').value === '';
  $('fess-confirm').disabled ||= !fessState?.pending;
  $('fess-rollback').disabled ||= !fessState?.pending;
  $('fess-apply').disabled ||= !!fessState?.pending || fessDirty;
  $('fess-plan').disabled ||= fessDirty;
  for (const field of fessForm.querySelectorAll('input, select, textarea')) field.disabled = fessBusy;
}

function fessRenderSite() {
  const site = fessDraft.config.sites[$('fess-site').value];
  const f = fessForm.elements;
  for (const field of ['host', 'upstream', 'certificate']) f[field].value = site?.[field] || '';
  f.path.value = site?.path || '/';
  f.mode.value = site?.mode || 'log';
  f.rules.value = JSON.stringify(site?.rules || [], null, 2);
  f.use_pack.checked = !!site?.use_pack;
  $('fess-pack').textContent = site?.pack ? site.pack.id + ' · ' + site.pack.version : '';
  fessButtons();
}

function fessRender(index = '') {
  const c = fessDraft.config;
  fessForm.elements.enabled.checked = c.enabled;
  fessForm.elements.tls.checked = c.tls;
  fessForm.elements.listen.value = c.listen;
  $('fess-site').replaceChildren(new Option('Новый маршрут', ''), ...c.sites.map((s, i) => new Option(s.host + s.path, i)));
  $('fess-site').value = String(index);
  fessRenderSite();
}

async function fessUpdateState() {
  const session = fessGeneration;
  const state = await api('/fess/state');
  if (session !== fessGeneration) return;
  fessState = state;
  $('fess-state').textContent = [
    state.enabled ? (state.tls ? 'HTTPS · ' : 'HTTP · ') + state.listen : 'FESS выключен',
    'Подтверждённая ревизия ' + state.revision,
    state.pending ? 'Подтвердить до ' + new Date(state.pending.deadline).toLocaleTimeString('ru-RU') : '',
    state.error || ''
  ].filter(Boolean).join(' · ');
  fessButtons();
}

async function refreshFESS() {
  const session = fessGeneration;
  try {
    const [draft, pki] = await Promise.all([api('/fess/config'), api('/pki')]);
    if (session !== fessGeneration || fessBusy || fessDirty) return;
    fessDraft = draft;
    fessForm.elements.certificate.replaceChildren(new Option('Выберите сертификат', ''), ...(pki.certificates || [])
      .filter(c => !c.revoked_at && c.kind !== 'ca').map(c => new Option(c.name, c.id)));
    fessRender(draft.config.sites.length ? 0 : '');
    await fessUpdateState();
  } catch (error) {
    if (session === fessGeneration) $('fess-result').textContent = error.message;
  }
}

async function fessAction(action) {
  if (fessBusy || !fessDraft) return;
  const session = fessGeneration;
  fessBusy = true;
  fessButtons();
  $('fess-result').textContent = '';
  try {
    await action(session);
    if (session === fessGeneration) await fessUpdateState();
  } catch (error) {
    if (session === fessGeneration) $('fess-result').textContent = error.message;
  } finally {
    if (session === fessGeneration) {
      fessBusy = false;
      fessButtons();
    }
  }
}

async function fessSave(remove = false) {
  const f = fessForm.elements;
  const index = $('fess-site').value;
  const c = structuredClone(fessDraft.config);
  Object.assign(c, {enabled: f.enabled.checked, tls: f.tls.checked, listen: f.listen.value.trim()});
  if (remove) {
    c.sites.splice(Number(index), 1);
  } else if (f.host.value.trim() || index !== '') {
    const site = c.sites[index] || {};
    Object.assign(site, {
      host: f.host.value.trim().toLowerCase(), path: f.path.value.trim(), upstream: f.upstream.value.trim(),
      certificate: f.certificate.value, mode: f.mode.value, rules: JSON.parse(f.rules.value || '[]'), use_pack: f.use_pack.checked
    });
    if (index === '') c.sites.push(site);
  }
  return api('/fess/config', {method: 'PUT', body: JSON.stringify({revision:fessDraft.revision, config:c})});
}

fessForm.addEventListener('input', event => {
  if (event.target.id === 'fess-site') return;
  fessDirty = true;
  fessButtons();
});
$('fess-site').addEventListener('change', fessRenderSite);
fessForm.addEventListener('submit', event => {
  event.preventDefault();
  void fessAction(async session => {
    const index = $('fess-site').value;
    const saved = await fessSave();
    if (session !== fessGeneration) return;
    fessDraft = saved;
    fessDirty = false;
    fessRender(index === '' && saved.config.sites.length ? saved.config.sites.length - 1 : index);
    $('fess-result').textContent = 'Черновик сохранён';
  });
});
$('fess-delete').addEventListener('click', () => fessAction(async session => {
  const saved = await fessSave(true);
  if (session !== fessGeneration) return;
  fessDraft = saved;
  fessDirty = false;
  fessRender();
}));
$('fess-plan').addEventListener('click', () => fessAction(async session => {
  const plan = await api('/fess/plan', {method:'POST', body:'{}'});
  if (session === fessGeneration) $('fess-result').textContent = 'Проверена ревизия ' + plan.revision;
}));
$('fess-apply').addEventListener('click', () => fessAction(() => api('/fess/apply', {
  method:'POST', body:JSON.stringify({revision:fessDraft.revision,timeout_seconds:120})
})));
for (const action of ['confirm','rollback']) {
  $('fess-'+action).addEventListener('click', () => fessAction(() => api('/fess/changes/'+fessState.pending.id+'/'+action, {method:'POST',body:'{}'})));
}
$('fess-catalog').addEventListener('click', () => fessAction(async session => {
  const result = await api('/fess/waf/catalog');
  if (session !== fessGeneration) return;
  fessPacks = result;
  $('fess-feed-pack').replaceChildren(new Option('Выберите набор',''), ...result.map((p,i) => new Option(p.title+' · '+p.version,i)));
}));
$('fess-feed-pack').addEventListener('change', fessButtons);
$('fess-import').addEventListener('click', () => fessAction(async session => {
  const index = $('fess-site').value;
  const {host,path} = fessDraft.config.sites[index];
  const pack = fessPacks[$('fess-feed-pack').value];
  const draft = await api('/fess/waf/import', {method:'POST',body:JSON.stringify({revision:fessDraft.revision,host,path,...pack})});
  if (session !== fessGeneration) return;
  fessDraft = draft;
  fessRender(index);
  $('fess-result').textContent = 'Набор импортирован. Включите его в настройках маршрута.';
}));
$('fess-events-refresh').addEventListener('click', () => fessAction(async session => {
  const events = await api('/fess/events');
  if (session !== fessGeneration) return;
  $('fess-events').replaceChildren(...events.map(e => node('li', [
    new Date(e.at).toLocaleString('ru-RU'), e.decision === 'block' ? 'Блокировка' : 'Запись', e.host+e.path, e.client, e.rule
  ].join(' · '), 'py-2 break-all')));
  if (!events.length) $('fess-events').append(node('li','Срабатываний пока нет','py-2 text-slate-600'));
}));
function resetFESS() {
  fessGeneration++;
  fessDraft = fessState = null;
  fessBusy = fessDirty = false;
  fessPacks = [];
  fessForm.reset();
  for (const id of ['fess-site','fess-events','fess-feed-pack','fess-result','fess-state']) $(id).replaceChildren();
  fessButtons();
}
setInterval(() => {
  if (fessDraft && !fessBusy && !$('app').hidden && location.hash === '#fess') void fessUpdateState().catch(() => {});
}, 5000);
