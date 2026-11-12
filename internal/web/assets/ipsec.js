'use strict';

let ipsecDraft = null;
let ipsecState = null;
let ipsecBusy = false;
let ipsecRefreshing = false;

function ipsecButtons() {
  const pending = ipsecState?.agent.pending;
  $('ipsec-apply').disabled = ipsecBusy || !ipsecDraft || !ipsecState?.agent.enabled || Boolean(pending);
  $('ipsec-plan').disabled = ipsecBusy || !ipsecDraft;
  $('ipsec-confirm').disabled = ipsecBusy || pending?.kind !== 'ipsec' || pending.status !== 'pending';
  $('ipsec-rollback').disabled = ipsecBusy || pending?.kind !== 'ipsec';
  $('ipsec-logs').disabled = !ipsecState?.agent.enabled;
}

function renderIPsec() {
  const agent = ipsecState?.agent;
  const pending = agent?.pending;
  $('ipsec-status').textContent = agent?.runtime_error || (agent?.enabled
    ? `Черновик ${ipsecDraft?.revision ?? '—'} · подтверждённая ревизия ${agent.confirmed_revision || '—'}`
    : 'Применение доступно через Linux-агент с IPsec.');
  const sync = ipsecState?.crl_sync;
  $('ipsec-crl').textContent = sync?.error ? 'Доставка CRL ожидает повторной попытки · ' + sync.error : '';
  $('ipsec-pending').hidden = !pending;
  if (pending) {
    const seconds = Math.max(0, Math.ceil((Date.parse(pending.deadline) - Date.now()) / 1000));
    $('ipsec-pending-text').textContent = pending.kind === 'ipsec'
      ? `Изменение IPsec · ${pending.status} · осталось ${seconds} с${pending.error ? ' · ' + pending.error : ''}`
      : 'На агенте ожидает подтверждения изменение другого модуля.';
  }
  const configured = ipsecDraft?.config.tunnels ?? [];
  const active = agent?.active?.tunnels ?? [];
  const list = $('ipsec-tunnels');
  list.replaceChildren();
  for (const tunnel of [...configured, ...active.filter(t => !configured.some(d => d.id === t.id))]) {
    const state = agent?.runtime?.find(t => t.id === tunnel.id);
    const inDraft = configured.some(t => t.id === tunnel.id);
    const box = node('div', '', 'rounded-lg border p-3');
    box.append(node('p', tunnel.name + ' · ' + tunnel.interface, 'font-medium'));
    box.append(node('p', `${tunnel.local_address} → ${tunnel.auth ? 'Удалённый доступ · ' + tunnel.public_endpoint : tunnel.remote_address}`, 'text-xs text-slate-500'));
    box.append(node('p', state?.blocked || (state?.established ? 'Туннель установлен'
      : state?.loaded ? 'Конфигурация загружена · ожидание соединения' : 'Туннель не активен'), 'mt-1 text-sm'));
    if (state?.crl_number) box.append(node('p', 'CRL № ' + state.crl_number, 'text-xs text-slate-500'));
    if (state?.details) box.append(node('pre', state.details, 'mt-2 whitespace-pre-wrap break-words text-xs'));
    if (inDraft) {
      const actions = node('div', '', 'mt-2 flex gap-4 text-sm');
      const edit = node('button', 'Изменить', 'text-teal-800');
      edit.addEventListener('click', () => editIPsec(tunnel));
      const remove = node('button', 'Удалить из черновика', 'text-red-700');
      remove.addEventListener('click', () => runIPsec(async () => {
        await saveIPsec(configured.filter(t => t.id !== tunnel.id));
        if ($('ipsec-form').elements.id.value === tunnel.id) {
          $('ipsec-form').reset();
          $('ipsec-form').elements.id.value = '';
    ipsecMode();
        }
      }));
      actions.append(edit, remove);
      box.append(actions);
    } else {
      box.append(node('p', 'Удалён из черновика', 'text-xs text-slate-500'));
    }
    list.append(box);
  }
  if (!list.children.length) list.append(node('p', 'Туннели ещё не настроены.', 'text-sm text-slate-500'));
  ipsecButtons();
}

async function refreshIPsec() {
  if ($('app').hidden || $('page-ipsec').hidden || ipsecBusy || ipsecRefreshing) return;
  ipsecRefreshing = true;
  try {
    const [draft, state, pki] = await Promise.all([api('/ipsec/config'), api('/ipsec/state'), api('/pki')]);
    ipsecDraft = draft;
    ipsecState = state;
    for (const field of ['certificate_id', 'peer_certificate_id']) {
      const select = $('ipsec-form').elements[field];
      const previous = select.value;
      select.replaceChildren(new Option('Выберите сертификат', ''));
      for (const c of pki.certificates.filter(c => c.kind === 'local')) {
        select.add(new Option(c.name + (c.revoked_at ? ' · отозван' : ''), c.id));
      }
      if ([...select.options].some(option => option.value === previous)) select.value = previous;
    }
    renderIPsec();
  } catch (err) {
    $('ipsec-status').textContent = err.message;
  } finally {
    ipsecRefreshing = false;
  }
}

async function runIPsec(action) {
  if (ipsecBusy || ipsecRefreshing) return;
  ipsecBusy = true;
  ipsecButtons();
  try {
    await action();
  } catch (err) {
    message(err.message);
  } finally {
    ipsecBusy = false;
    ipsecButtons();
    await refreshIPsec();
  }
}
async function saveIPsec(tunnels) {
  ipsecDraft = await api('/ipsec/config', {
    method: 'PUT',
    headers: { 'If-Match': JSON.stringify(String(ipsecDraft.revision)) },
    body: JSON.stringify({ tunnels })
  });
  $('ipsec-preview').hidden = true;
  message('Черновик IPsec сохранён.');
}
function ipsecMode() {
  const form = $('ipsec-form');
  const access = form.elements.access_mode.value === 'user';
  const certificate = form.elements.auth_certificate.checked;
  $('ipsec-user-auth').hidden = !access;
  form.elements.remote_address.closest('label').hidden = access;
  form.elements.remote_address.required = !access;
  form.elements.public_endpoint.required = access;
  form.elements.client_user.required = access && certificate;
  form.elements.client_user.closest('label').hidden = !certificate;
  form.elements.peer_certificate_id.required = !access || certificate;
  form.elements.peer_certificate_id.closest('label').hidden = access && !certificate;
  form.elements.initiate.closest('label').hidden = access;
  $('ipsec-peer-label').textContent = access ? 'Клиентский сертификат' : 'Сертификат удалённого шлюза';
  $('ipsec-remote-label').textContent = access ? 'Пул IPv4 для клиентов (/16–/30)' : 'Удалённые подсети';
}

function editIPsec(tunnel) {
  const form = $('ipsec-form');
  form.reset();
  form.elements.access_mode.value = tunnel.auth ? 'user' : 'site';
  setVPNMethod(form, tunnel.auth);
  ipsecMode();
  for (const [key, value] of Object.entries(tunnel)) {
    const field = form.elements[key];
    if (!field) continue;
    if (field.type === 'checkbox') field.checked = value;
    else field.value = Array.isArray(value) ? value.join('\n') : value;
  }
  form.elements.name.focus();
}
$('ipsec-form').addEventListener('submit', event => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  void runIPsec(async () => {
    if (!ipsecDraft) return;
    const networks = key => String(data.get(key)).split(/[\s,]+/).filter(Boolean);
    const access = data.get('access_mode') === 'user';
    const auth = access ? vpnMethod($('ipsec-form')) : undefined;
    const tunnel = {
      auth,
      public_endpoint: access ? data.get('public_endpoint').trim() : '',
      client_user: access && auth.certificate ? data.get('client_user').trim() : '',
      id: data.get('id') || crypto.randomUUID().replaceAll('-', ''),
      name: String(data.get('name')).trim(),
      interface: String(data.get('interface')).trim(),
      enabled: data.has('enabled'),
      initiate: !access && data.has('initiate'),
      local_address: String(data.get('local_address')).trim(),
      remote_address: access ? '' : String(data.get('remote_address')).trim(),
      local_networks: networks('local_networks'),
      remote_networks: networks('remote_networks'),
      certificate_id: data.get('certificate_id'),
      peer_certificate_id: !access || auth.certificate ? data.get('peer_certificate_id') : ''
    };
    const tunnels = [...ipsecDraft.config.tunnels];
    const index = tunnels.findIndex(t => t.id === tunnel.id);
    if (index < 0) tunnels.push(tunnel);
    else tunnels[index] = tunnel;
    await saveIPsec(tunnels);
    $('ipsec-form').reset();
    $('ipsec-form').elements.id.value = '';
    ipsecMode();
  });
});
$('ipsec-reset').addEventListener('click', () => {
  $('ipsec-form').reset();
  $('ipsec-form').elements.id.value = '';
    ipsecMode();
});
$('ipsec-plan').addEventListener('click', () => void runIPsec(async () => {
  const plan = await api('/ipsec/plan', { method: 'POST', body: JSON.stringify(ipsecDraft.config) });
  $('ipsec-preview').textContent = [...plan.actions, ...plan.warnings].join('\n');
  $('ipsec-preview').hidden = false;
}));
$('ipsec-apply').addEventListener('click', () => void runIPsec(async () => {
  const timeout = $('ipsec-timeout');
  if (!timeout.reportValidity()) return;
  await api('/ipsec/apply', { method: 'POST', body: JSON.stringify({
    id: crypto.randomUUID(), revision: ipsecDraft.revision, timeout_seconds: Number(timeout.value)
  }) });
  message('IPsec ожидает подтверждения.');
}));
for (const action of ['confirm', 'rollback']) {
  $('ipsec-' + action).addEventListener('click', () => void runIPsec(async () => {
    const pending = ipsecState?.agent.pending;
    if (pending?.kind !== 'ipsec') return;
    await api('/ipsec/changes/' + encodeURIComponent(pending.id) + '/' + action, { method: 'POST', body: '{}' });
  }));
}
$('ipsec-logs').addEventListener('click', () => void runIPsec(async () => {
  const lines = await api('/ipsec/logs');
  $('ipsec-log-output').textContent = lines.join('\n') || 'Журнал пуст.';
  $('ipsec-log-output').hidden = false;
}));
setInterval(() => {
  if (!$('app').hidden && !$('page-ipsec').hidden) void refreshIPsec();
}, 4000);

for (const name of ['access_mode', 'auth_certificate']) $('ipsec-form').elements[name].addEventListener('change', ipsecMode);
ipsecMode();
