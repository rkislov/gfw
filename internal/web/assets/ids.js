'use strict';
let idsDraft = null, idsState = null, idsDirty = false, idsBusy = false;
let idsAlertsBefore = 0, idsAlertsBusy = false, idsSession = 0;
const idsForm = $('ids-form');

function idsConfig() {
  const form = new FormData(idsForm);
  return {
    enabled: form.has('enabled'),
    mode: form.get('mode'),
    failure_policy: form.get('mode') === 'ips' ? form.get('failure_policy') : '', 
    interfaces: form.getAll('interfaces'),
    home_net: form.get('home_net').split(/[\s,]+/).filter(Boolean),
    rules: form.get('rules')
  };
}

function idsButtons() {
  const pending = idsState?.pending;
  const own = pending?.kind === 'ids';
  $('ids-save').disabled = idsBusy || !idsDraft;
  $('ids-plan').disabled = idsBusy || !idsDraft;
  const pinned = idsDraft?.config.file_ioc?.snapshot_sha256;
  const active = idsState?.runtime.running && idsState.runtime.file_ioc_snapshot;
  $('ioc-file-stage').disabled = idsBusy || idsDirty || !idsDraft;
  $('ioc-file-disable').disabled = idsBusy || idsDirty || !pinned;
  $('ioc-file-pin').textContent = [
    pinned ? 'Черновик · ' + pinned : 'Снимок в черновике отсутствует',
    active ? 'Работает · ' + active : ''
  ].filter(Boolean).join(' · ');
  $('ids-apply').disabled = idsBusy || idsDirty || !idsDraft || !idsState?.enabled || !!pending;
  $('ids-pending').hidden = !pending;
  $('ids-pending-controls').hidden = !own;
  $('ids-confirm').disabled = idsBusy || !own || pending.status !== 'pending' || Date.parse(pending.deadline) <= Date.now();
  $('ids-rollback').disabled = idsBusy || !own;
  $('ids-alert-more').disabled = idsAlertsBusy;
  $('ids-alert-refresh').disabled = idsAlertsBusy;
  for (const field of idsForm.querySelectorAll('input, textarea, select')) field.disabled = idsBusy;
  $('ips-options').hidden = idsForm.elements.mode.value !== 'ips';
  if (!pending) return;
  if (!own) {
    $('ids-pending-text').textContent = 'Дождитесь завершения другого изменения на агенте.';
    return;
  }
  const seconds = Math.max(0, Math.ceil((Date.parse(pending.deadline) - Date.now()) / 1000));
  $('ids-pending-text').textContent = pending.status === 'pending'
    ? `Ревизия ${pending.revision} · до автоматического отката ${seconds} сек.`
    : (changeLabels[pending.status] || pending.status) + (pending.error ? ' · ' + pending.error : '');
}

function renderIDS(links) {
  const c = idsDraft.config;
  idsForm.elements.enabled.checked = c.enabled;
  idsForm.elements.mode.value = c.mode || 'ids';
  idsForm.elements.failure_policy.value = c.failure_policy || 'closed';
  idsForm.elements.home_net.value = c.home_net.join('\n');
  idsForm.elements.rules.value = c.rules;
  const devices = new Map(links.filter(l => !l.loopback && l.mac).map(l => [l.name, l.up]));
  for (const name of c.interfaces) if (!devices.has(name)) devices.set(name, false);
  const list = $('ids-interfaces');
  list.replaceChildren();
  for (const [name, up] of devices) {
    const label = node('label', '', 'flex items-center gap-2 rounded-lg border px-2 py-1');
    const input = node('input', '');
    input.type = 'checkbox';
    input.name = 'interfaces';
    input.value = name;
    input.checked = c.interfaces.includes(name);
    label.append(input, node('span', name + (up ? '' : ' · недоступен')));
    list.append(label);
  }
  if (!devices.size) list.append(node('span', 'Подходящие интерфейсы не найдены', 'text-slate-500'));
  $('ids-dirty').textContent = 'Сохранённая ревизия ' + idsDraft.revision;
  idsButtons();
}

async function pollIDS() {
  const session = idsSession;
  try {
    const state = await api('/ids/state');
    if (session !== idsSession) return;
    idsState = state;
    const runtime = state.runtime;
    const mode = runtime.mode === 'ips' ? 'IPS' : 'IDS';
    const revision = state.confirmed_revision || 'ещё нет';
    $('ids-state').textContent = !state.enabled ? 'Suricata недоступен на агенте. Можно подготовить черновик.' :
      `${runtime.running ? 'Suricata ' + mode + ' работает · ' + runtime.interfaces.join(', ') : 'Suricata остановлен'} · Подтверждённая ревизия ${revision}` +
      (runtime.error ? ' · ' + runtime.error : '') +
      (runtime.dropped_events ? ' · Не записано коллектором ' + runtime.dropped_events : '');
    const queue = runtime.queue;
    const failure = state.failure_policy === 'open' ? 'fail-open' : state.failure_policy === 'closed' ? 'fail-closed' : '';
    $('ips-state').textContent = [
      state.ips_queue && state.ips_hooked ? 'NFQUEUE ' + state.ips_queue : '',
      failure,
      queue ? `В очереди ${queue.waiting} · Потери ${queue.kernel_dropped + queue.user_dropped}` : '',
      state.ips_error || ''
    ].filter(Boolean).join(' · ');
  } catch (error) {
    if (session !== idsSession) return;
    idsState = null;
    $('ids-state').textContent = error.message;
    $('ips-state').textContent = '';
  }
  idsButtons();
}

async function refreshIDS() {
  const session = idsSession;
  await Promise.all([
    (async () => {
      if (idsDirty || idsBusy) return;
      try {
        const [draft, links] = await Promise.all([api('/ids/config'), api('/interfaces').catch(() => [])]);
        if (session !== idsSession || idsDirty || idsBusy) return;
        idsDraft = draft;
        renderIDS(links);
      } catch (error) {
        if (session === idsSession) $('ids-error').textContent = error.message;
      }
    })(),
    pollIDS(),
    loadIDSAlerts()
  ]);
}

async function idsAction(action) {
  if (!idsDraft || idsBusy) return;
  const session = idsSession;
  idsBusy = true;
  $('ids-error').textContent = '';
  idsButtons();
  try {
    await action();
  } catch (error) {
    if (session === idsSession) $('ids-error').textContent = error.message;
  } finally {
    if (session === idsSession) {
      idsBusy = false;
      await pollIDS();
      await pollChanges();
    }
  }
}

idsForm.addEventListener('input', () => {
  idsDirty = true;
  $('ids-preview').hidden = true;
  $('ids-dirty').textContent = 'Есть несохранённые изменения';
  idsButtons();
});

idsForm.addEventListener('submit', event => {
  event.preventDefault();
  const config = idsConfig();
  const session = idsSession;
  void idsAction(async () => {
    const saved = await api('/ids/config', {
      method: 'PUT', headers: {'If-Match': JSON.stringify(String(idsDraft.revision))}, body: JSON.stringify(config)
    });
    if (session !== idsSession) return;
    idsDraft = saved;
    idsDirty = false;
    $('ids-dirty').textContent = 'Сохранённая ревизия ' + saved.revision;
  });
});

$('ids-plan').addEventListener('click', () => {
  const config = idsConfig();
  const session = idsSession;
  void idsAction(async () => {
    const plan = await api('/ids/plan', {method: 'POST', body: JSON.stringify(config)});
    if (session !== idsSession) return;
    $('ids-preview').textContent = [...plan.actions, ...plan.warnings].join('\n');
    $('ids-preview').hidden = false;
  });
});

$('ids-apply').addEventListener('click', () => {
  if (idsDirty || !idsDraft || idsState?.pending) return;
  const seconds = Number($('ids-timeout').value);
  if (!Number.isInteger(seconds) || seconds < 30 || seconds > 600) {
    $('ids-error').textContent = 'Укажите срок подтверждения 30–600 секунд.';
    return;
  }
  void idsAction(() => api('/ids/apply', {
    method: 'POST', body: JSON.stringify({id: crypto.randomUUID(), revision: idsDraft.revision, timeout_seconds: seconds})
  }));
});

for (const action of ['confirm', 'rollback']) {
  $('ids-' + action).addEventListener('click', () => {
    const p = idsState?.pending;
    if (p?.kind !== 'ids') return;
    void idsAction(() => api('/ids/changes/' + encodeURIComponent(p.id) + '/' + action, {method: 'POST', body: '{}'}));
  });
}

$('ids-logs').addEventListener('click', async () => {
  const session = idsSession;
  try {
    const lines = await api('/ids/logs');
    if (session !== idsSession) return;
    $('ids-log-output').textContent = lines.join('\n') || 'Журнал движка пуст.';
    $('ids-log-output').hidden = false;
  } catch (error) {
    if (session === idsSession) $('ids-error').textContent = error.message;
  }
});

async function loadIDSAlerts(older = false) {
  if (idsAlertsBusy || older && !idsAlertsBefore) return;
  const session = idsSession;
  idsAlertsBusy = true;
  idsButtons();
  try {
    const alerts = await api('/ids/alerts' + (older ? '?before=' + idsAlertsBefore : ''));
    if (session !== idsSession) return;
    const list = $('ids-alerts');
    if (!older) list.replaceChildren();
    for (const alert of alerts) {
      const item = node('li', '', 'py-3');
      const address = (host, port) => port ? (host.includes(':') ? '[' + host + ']:' + port : host + ':' + port) : host;
      item.append(node('p', alert.message, 'break-words text-sm font-medium'));
      item.append(node('p', `${new Date(alert.at).toLocaleString('ru-RU')} · ${alert.interface ? alert.interface + ' · ' : ''}${alert.protocol} · ${alert.action === 'blocked' ? 'Заблокировано · ' : ''}SID ${alert.sid} · Приоритет ${alert.severity}`, 'mt-1 text-xs text-slate-600'));
      item.append(node('p', address(alert.src, alert.src_port) + ' → ' + address(alert.dst, alert.dst_port), 'mt-1 break-all font-mono text-xs text-slate-600'));
      list.append(item);
    }
    idsAlertsBefore = alerts.length === 100 && list.children.length < 1000 ? alerts.at(-1).id : 0;
    $('ids-alert-more').hidden = !idsAlertsBefore;
    $('ids-alert-status').textContent = list.children.length ? `Показано ${list.children.length} алертов` : 'Алертов пока нет.';
  } catch (error) {
    if (session === idsSession) $('ids-alert-status').textContent = error.message;
  } finally {
    if (session === idsSession) {
      idsAlertsBusy = false;
      idsButtons();
    }
  }
}

$('ids-alert-refresh').addEventListener('click', () => loadIDSAlerts());
$('ids-alert-more').addEventListener('click', () => loadIDSAlerts(true));

async function stageIDSFileIOC(enable) {
  if (idsDirty) return;
  const session = idsSession;
  await idsAction(async () => {
    const latest = enable ? (await api('/feed')).entries.find(entry => entry.name === 'iocs.json') : null;
    if (session !== idsSession) return;
    if (enable && !latest) throw new Error('Сначала загрузите IOC в разделе Security Feed.');
    const draft = await api('/ids/file-ioc/stage', {
      method: 'POST', body: JSON.stringify({revision: idsDraft.revision, snapshot_sha256: latest?.sha256 || ''})
    });
    if (session !== idsSession) return;
    idsDraft = draft;
    $('ids-preview').hidden = true;
    $('ids-dirty').textContent = 'Сохранённая ревизия ' + draft.revision;
  });
}

$('ioc-file-stage').addEventListener('click', () => stageIDSFileIOC(true));
$('ioc-file-disable').addEventListener('click', () => stageIDSFileIOC(false));
$('ioc-file-form').addEventListener('submit', async event => {
  event.preventDefault();
  const file = $('ioc-file').files[0];
  if (!file) return;
  const output = $('ioc-file-result');
  const button = $('ioc-file-check');
  const session = idsSession;
  output.hidden = false;
  if (file.size > 16 * 1024 * 1024) {
    output.textContent = 'Файл больше 16 МиБ.';
    return;
  }
  button.disabled = true;
  output.textContent = 'Вычисляем хэши и проверяем IOC…';
  try {
    const data = await api('/ids/file-ioc/scan', {
      method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: file
    });
    if (session !== idsSession) return;
    const matches = data.matches.map(m => [m.algorithm.toUpperCase(), m.hash, m.source, m.threat].filter(Boolean).join(' · '));
    output.textContent = [
      data.matches.length ? 'Найдены совпадения с IOC' : 'Совпадений в этом снимке нет',
      data.snapshot_at ? 'Снимок от ' + new Date(data.snapshot_at).toLocaleString('ru-RU') : '',
      'SHA-256 файла · ' + data.hashes.sha256,
      ...matches,
      data.more_matches ? 'Показаны первые 20 совпадений.' : ''
    ].filter(Boolean).join('\n');
  } catch (error) {
    if (session === idsSession) output.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

function resetIDS() {
  idsSession++;
  $('ioc-file-form').reset();
  $('ioc-file-result').replaceChildren();
  $('ioc-file-result').hidden = true;
  idsDraft = idsState = null;
  idsDirty = idsBusy = idsAlertsBusy = false;
  idsAlertsBefore = 0;
  idsForm.reset();
  for (const id of ['ids-interfaces', 'ids-alerts', 'ids-log-output', 'ids-error', 'ids-state', 'ips-state', 'ids-dirty', 'ids-preview', 'ids-alert-status']) $(id).replaceChildren();
  for (const id of ['ids-preview', 'ids-log-output', 'ids-alert-more']) $(id).hidden = true;
  idsButtons();
}

setInterval(() => {
  if (!$('page-ids').hidden && !$('app').hidden && !idsBusy) void pollIDS();
}, 3000);
setInterval(() => { if (!$('page-ids').hidden) idsButtons(); }, 1000);
