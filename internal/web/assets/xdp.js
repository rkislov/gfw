'use strict';

const xdpForm = $('xdp-form');
let xdpState = null, xdpRevision = null, xdpLoading = false, xdpBusy = false, xdpSession = 0;

function xdpList(value) {
  return value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}

function xdpID() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
}

function renderXDPForm(state, reset) {
  const controls = xdpForm.elements;
  const confirmed = state.confirmed;
  const selected = reset ? confirmed.interfaces || [] : [...xdpForm.querySelectorAll('input[name="interface"]:checked')].map(input => input.value);
  $('xdp-interfaces').replaceChildren(...state.wan.map(name => {
    const label = node('label', '', 'flex items-center gap-2 rounded-lg border px-3 py-2 text-sm');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.name = 'interface';
    box.value = name;
    box.checked = selected.includes(name);
    label.append(box, node('span', name));
    return label;
  }));
  if (!state.wan.length) $('xdp-interfaces').append(node('p', 'Назначьте интерфейс зоне WAN и подтвердите политику межсетевого экрана.', 'text-sm text-slate-500'));
  const feed = controls.feed_sha256;
  const selectedFeed = reset ? confirmed.feed?.sha256 || '' : feed.value;
  feed.replaceChildren(new Option('Без подписки', ''));
  const available = state.available_feed;
  if (confirmed.feed && confirmed.feed.sha256 !== available?.sha256) {
    const old = confirmed.feed;
    feed.append(new Option(`Действующий снимок · ${old.count} записей · ${old.sha256.slice(0, 12)}`, old.sha256));
  }
  if (available) feed.append(new Option(`Последний загруженный · ${available.count} записей · ${available.sha256.slice(0, 12)}`, available.sha256));
  if (selectedFeed && ![...feed.options].some(option => option.value === selectedFeed)) {
    const expired = new Option('Выбранный снимок сменился. Выберите доступный снимок.', selectedFeed);
    expired.disabled = true;
    feed.append(expired);
  }
  feed.value = selectedFeed;
  if (reset) {
    controls.mode.value = confirmed.mode || 'native';
    controls.match.value = confirmed.match || 'source';
    controls.block.value = (confirmed.block || []).join('\n');
    controls.exceptions.value = (confirmed.exceptions || []).join('\n');
  }
}

function renderXDPCounters(state) {
  const number = new Intl.NumberFormat('ru-RU');
  const rows = state.runtime.map(port => {
    const row = node('tr', '');
    row.append(node('td', port.name, 'p-3 font-medium'));
    for (const [packets, bytes] of [[port.passed, port.passed_bytes], [port.manual_drops, port.manual_bytes], [port.feed_drops, port.feed_bytes]]) {
      const cell = node('td', number.format(packets) + ' пак.', 'p-3 whitespace-nowrap');
      cell.append(node('div', number.format(bytes) + ' байт', 'text-xs text-slate-500'));
      row.append(cell);
    }
    return row;
  });
  $('xdp-counter-rows').replaceChildren(...rows);
  $('xdp-counter-empty').hidden = rows.length > 0;
  $('xdp-counter-table').hidden = rows.length === 0;
}

function renderXDPButtons() {
  const state = xdpState;
  const pending = state?.pending;
  const own = pending?.kind === 'xdp' ? pending : null;
  $('xdp-fields').disabled = !state?.enabled || !!pending || xdpBusy;
  $('xdp-apply').disabled = !state?.wan.length;
  $('xdp-disable').disabled = !state?.confirmed.interfaces?.length;
  $('xdp-pending').hidden = !own;
  if (!own) return;
  const seconds = Math.max(0, Math.ceil((Date.parse(own.deadline) - Date.now()) / 1000));
  const profile = state.target?.interfaces?.length ? ' · ' + state.target.interfaces.join(', ') : ' · отключение профиля';
  const status = own.status === 'pending' && seconds > 0 ? `До автоматического отката ${seconds} сек.` :
    own.status === 'pending' ? 'Ожидается автоматический откат' : changeLabels[own.status] || own.status;
  $('xdp-deadline').textContent = status + profile;
  $('xdp-confirm').disabled = xdpBusy || own.status !== 'pending' || seconds === 0;
  $('xdp-rollback').disabled = xdpBusy;
}

async function refreshXDP() {
  if (xdpLoading || $('app').hidden) return;
  const session = xdpSession;
  xdpLoading = true;
  try {
    const state = await api('/xdp/state');
    if (session !== xdpSession) return;
    const before = xdpState;
    xdpState = state;
    if (!before || xdpRevision !== state.revision || before.available_feed?.sha256 !== state.available_feed?.sha256 ||
        before.wan.join(',') !== state.wan.join(',')) {
      renderXDPForm(state, xdpRevision !== state.revision);
    }
    xdpRevision = state.revision;
    $('xdp-status').textContent = !state.enabled ? 'Для ранней фильтрации нужен Linux-агент с модулем XDP.' :
      state.pending && state.pending.kind !== 'xdp' ? 'Завершите другое изменение, прежде чем применять профиль XDP.' :
        `Подтверждённая ревизия ${state.revision} · ${state.confirmed.interfaces?.length ? 'настроен' : 'профиль выключен'}`;
    $('xdp-runtime-error').textContent = state.error || '';
    const last = state.history.at(-1);
    $('xdp-last-change').textContent = last ?
      `Последнее изменение · ${changeLabels[last.status] || last.status} · ревизия ${last.revision}` : '';
    renderXDPCounters(state);
    renderXDPButtons();
  } catch (err) {
    if (session !== xdpSession) return;
    xdpState = null;
    renderXDPButtons();
    $('xdp-runtime-error').textContent = err.message;
  } finally {
    if (session === xdpSession) xdpLoading = false;
  }
}

async function xdpChange(path, body) {
  const session = xdpSession;
  xdpBusy = true;
  renderXDPButtons();
  $('xdp-note').textContent = '';
  try {
    const result = await api(path, {method: 'POST', body: JSON.stringify(body)});
    if (session !== xdpSession) return;
    $('xdp-note').textContent = changeLabels[result.status] || result.status;
  } catch (err) {
    if (session === xdpSession) $('xdp-note').textContent = err.message;
  } finally {
    if (session === xdpSession) {
      xdpBusy = false;
      await refreshXDP();
      renderXDPButtons();
    }
  }
}

function submitXDP(disable) {
  if (xdpBusy || !xdpState?.enabled || xdpState.pending) return;
  const fields = new FormData(xdpForm);
  const profile = disable ? {interfaces: []} : {
    interfaces: fields.getAll('interface'), mode: fields.get('mode'), match: fields.get('match'),
    block: xdpList(fields.get('block')), feed_sha256: fields.get('feed_sha256') || '',
    exceptions: xdpList(fields.get('exceptions'))
  };
  if (!disable && !profile.interfaces.length) {
    $('xdp-note').textContent = 'Выберите хотя бы один интерфейс WAN.';
    return;
  }
  if (!disable && xdpForm.elements.feed_sha256.selectedOptions[0]?.disabled) {
    $('xdp-note').textContent = 'Выберите доступный снимок Security Feed.';
    return;
  }
  void xdpChange('/xdp/apply', {id: xdpID(), revision: xdpState.revision, timeout_seconds: Number(fields.get('timeout')), profile});
}

function resetXDP() {
  xdpSession++;
  xdpState = null;
  xdpRevision = null;
  xdpLoading = false;
  xdpBusy = false;
  xdpForm.reset();
  for (const id of ['xdp-interfaces', 'xdp-counter-rows', 'xdp-note', 'xdp-last-change', 'xdp-runtime-error']) $(id).replaceChildren();
  $('xdp-counter-table').hidden = true;
  $('xdp-counter-empty').hidden = false;
  renderXDPButtons();
}

xdpForm.addEventListener('submit', event => { event.preventDefault(); submitXDP(false); });
$('xdp-disable').addEventListener('click', () => { if (xdpForm.reportValidity()) submitXDP(true); });
$('xdp-refresh').addEventListener('click', refreshXDP);
for (const action of ['confirm', 'rollback']) {
  $('xdp-' + action).addEventListener('click', () => {
    const pending = xdpState?.pending;
    if (pending?.kind === 'xdp') void xdpChange('/xdp/changes/' + encodeURIComponent(pending.id) + '/' + action, {});
  });
}
setInterval(() => {
  if (!$('app').hidden && !$('page-xdp').hidden) {
    renderXDPButtons();
    void refreshXDP();
  }
}, 2000);
