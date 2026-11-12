'use strict';

const captureForm = $('capture-form');
const captureBackends = {xdp: 'XDP в драйвере', 'xdp-generic': 'XDP generic', packet: 'AF_PACKET'};
const captureDirections = {in: 'Входящие', out: 'Исходящие', inout: 'Входящие и исходящие'};
const captureStates = {running: 'Идёт захват', complete: 'Завершён', incomplete: 'Неполный захват'};
const captureReasons = {manual: 'Остановлен вручную', duration: 'Лимит времени', packets: 'Лимит пакетов', size: 'Лимит размера', shutdown: 'Остановка агента', restart: 'Перезапуск агента'};
let captureGeneration = 0, captureLoading = false, captureRunning = false;

function captureMiB(bytes) {
  return (bytes / 1048576).toLocaleString('ru-RU', {maximumFractionDigits: 2}) + ' МиБ';
}

function captureNotice(text) {
  $('capture-note').textContent = text;
}

function captureRow(session) {
  const row = node('div', '', 'py-4');
  const headline = node('div', '', 'flex flex-wrap items-center justify-between gap-3');
  const summary = node('div', '', 'flex flex-wrap items-center gap-3');
  summary.append(node('strong', session.config.interface, 'text-sm'),
    node('span', captureStates[session.state] || session.state, 'text-sm font-medium'),
    node('span', captureBackends[session.backend] + ' · ' + captureDirections[session.config.direction], 'text-xs text-slate-500'));
  const actions = node('div', '', 'flex flex-wrap gap-2');
  const buttonClass = 'rounded-lg border px-3 py-2 text-sm';
  if (session.state === 'running') {
    const stop = node('button', 'Остановить', buttonClass);
    stop.addEventListener('click', () => captureAction(stop, session, 'stop'));
    actions.append(stop);
  } else {
    if (session.sha256) {
      const download = node('a', 'Скачать PCAP', buttonClass + ' text-teal-800');
      download.href = '/api/v1/captures/' + encodeURIComponent(session.id) + '/file';
      download.download = 'gfw-' + session.id + '.pcap';
      actions.append(download);
    }
    const remove = node('button', 'Удалить', buttonClass + ' text-red-700');
    remove.addEventListener('click', () => {
      if (window.confirm('Удалить файл и запись этой сессии?')) void captureAction(remove, session, 'delete');
    });
    actions.append(remove);
  }
  headline.append(summary, actions);
  row.append(headline);
  const details = [new Date(session.start).toLocaleString('ru-RU'), `Пакеты ${session.packets}`, captureMiB(session.bytes)];
  if (session.truncated) details.push(`Усечено ${session.truncated}`);
  if (session.reason) details.push(captureReasons[session.reason] || session.reason);
  if (session.dropped != null) details.push(`Потери ${session.dropped}`);
  else if (session.state !== 'running') details.push('Потери неизвестны');
  row.append(node('p', details.join(' · '), 'mt-2 text-xs text-slate-600'));
  if (session.filter) row.append(node('p', session.filter, 'mt-2 break-all font-mono text-xs'));
  if (session.fallback) row.append(node('p', 'Переход на AF_PACKET · ' + session.fallback, 'mt-2 break-all text-xs text-slate-500'));
  if (session.error) row.append(node('p', session.error, 'mt-2 break-all text-xs text-red-700'));
  if (session.sha256) {
    const disclosure = node('details', '', 'mt-2 text-xs text-slate-500');
    disclosure.append(node('summary', 'Хранение и контрольная сумма', 'cursor-pointer'),
      node('div', 'Удаление ' + new Date(session.expires).toLocaleString('ru-RU'), 'mt-2'),
      node('div', 'SHA-256 ' + session.sha256, 'break-all font-mono'));
    row.append(disclosure);
  }
  return row;
}

async function refreshCapture(loadInterfaces = false) {
  if (captureLoading || $('app').hidden) return;
  const generation = captureGeneration;
  captureLoading = true;
  try {
    const [state, links] = await Promise.all([
      api('/captures'), loadInterfaces ? api('/interfaces').catch(() => null) : null
    ]);
    if (captureGeneration !== generation) return;
    captureRunning = state.sessions.some(session => session.state === 'running');
    $('capture-fields').disabled = !state.enabled || captureRunning;
    $('capture-health').textContent = !state.enabled ? 'Для захвата подключите Linux-агент.' :
      captureRunning ? 'Активен один захват. Его можно остановить в списке.' :
        'XDP доступен для входящего трафика. AF_PACKET поддерживает оба направления.';
    $('capture-storage').textContent = state.enabled ? `На диске ${captureMiB(state.used)} из ${captureMiB(state.quota)}` : '';
    if (links) {
      const control = captureForm.elements.interface;
      const previous = control.value;
      control.replaceChildren(new Option('Выберите интерфейс', ''), ...links.filter(link => link.up).map(link => new Option(link.name, link.name)));
      if (links.some(link => link.up && link.name === previous)) control.value = previous;
    }
    $('capture-sessions').replaceChildren(...state.sessions.map(captureRow));
    if (!state.sessions.length) $('capture-sessions').append(node('p', 'Сессий захвата пока нет.', 'py-4 text-sm text-slate-500'));
  } catch (err) {
    if (captureGeneration !== generation) return;
    $('capture-fields').disabled = true;
    $('capture-health').textContent = err.message;
  } finally {
    if (captureGeneration === generation) captureLoading = false;
  }
}

async function captureAction(button, session, action) {
  const generation = captureGeneration;
  button.disabled = true;
  try {
    const path = '/captures/' + encodeURIComponent(session.id);
    await api(path + (action === 'stop' ? '/stop' : ''), {method: action === 'stop' ? 'POST' : 'DELETE'});
    if (captureGeneration !== generation) return;
    captureNotice(action === 'stop' ? 'Останавливаем захват и закрываем файл.' : 'Сессия удалена.');
    await refreshCapture();
  } catch (err) {
    if (captureGeneration === generation) captureNotice(err.message);
  } finally {
    button.disabled = false;
  }
}

function resetCapture() {
  captureGeneration++;
  captureLoading = false;
  captureRunning = false;
  captureForm.reset();
  captureForm.elements.interface.replaceChildren(new Option('Выберите интерфейс', ''));
  $('capture-fields').disabled = true;
  for (const id of ['capture-health', 'capture-note', 'capture-storage', 'capture-sessions']) $(id).replaceChildren();
}

captureForm.elements.backend.addEventListener('change', event => {
  if (event.target.value.startsWith('xdp')) captureForm.elements.direction.value = 'in';
});
captureForm.addEventListener('submit', async event => {
  event.preventDefault();
  const generation = captureGeneration;
  const config = Object.fromEntries(new FormData(captureForm));
  for (const key of ['seconds', 'max_mib', 'max_packets', 'snaplen', 'retention_hours']) config[key] = Number(config[key] || 0);
  config.vlan = config.vlan === '' ? null : Number(config.vlan);
  event.submitter.disabled = true;
  try {
    await api('/captures', {method: 'POST', body: JSON.stringify(config)});
    if (captureGeneration !== generation) return;
    captureRunning = true;
    captureNotice('Захват запущен.');
    await refreshCapture();
  } catch (err) {
    if (captureGeneration === generation) captureNotice(err.message);
  } finally {
    event.submitter.disabled = false;
  }
});
$('capture-refresh').addEventListener('click', () => refreshCapture(true));
setInterval(() => {
  if (!$('page-capture').hidden && !$('app').hidden) void refreshCapture();
}, 2500);
