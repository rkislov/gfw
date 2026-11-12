'use strict';
let feedState = null, feedBusy = false, feedGeneration = 0;
const feedFileNames = {
  'catalog.json': 'Каталог подписки', 'ips.txt': 'IP-адреса и сети',
  'domains.txt': 'Домены', 'iocs.json': 'Индикаторы угроз (IOC)'
};

function feedButtons() {
  $('feed-save').disabled = feedBusy || !feedState;
  for (const id of ['feed-check', 'feed-remove', 'feed-refresh']) {
    $(id).disabled = feedBusy || !feedState?.has_key;
  }
  renderFeedConsumers();
}

function renderFeed(data, syncSettings = false) {
  feedState = data;
  $('feed-key-status').textContent = data.has_key ? 'Ключ сохранён' : 'Ключ не задан';
  $('feed-key').placeholder = data.has_key ? 'Введите новый ключ для замены' : '';
  if (syncSettings) $('feed-hours').value = data.interval_hours;
  const last = data.success_at ? new Date(data.success_at).toLocaleString('ru-RU') : '';
  const attempt = data.attempt_at ? new Date(data.attempt_at).toLocaleString('ru-RU') : '';
  $('feed-status').textContent = [
    last ? 'Последняя успешная загрузка · ' + last : 'Снимка ещё нет',
    data.stale ? 'Снимок устарел' : '',
    data.error && attempt ? 'Последняя попытка · ' + attempt : ''
  ].filter(Boolean).join(' · ');
  $('feed-error').textContent = data.error || '';
  $('feed-files').replaceChildren();
  for (const entry of data.entries) {
    const item = node('li', '', 'py-3');
    const title = feedFileNames[entry.name] || entry.name;
    item.append(node('p', title + (entry.count ? ' · ' + entry.count.toLocaleString('ru-RU') : ''), 'text-sm font-medium'));
    if (entry.source) item.append(node('p', 'Источник · ' + entry.source, 'text-xs text-slate-500'));
    item.append(node('p', 'SHA-256 ' + entry.sha256, 'break-all font-mono text-xs text-slate-500'));
    const path = '/api/v1/feed/files/' + encodeURIComponent(entry.name);
    const link = node('a', 'Исходный файл', 'mt-1 mr-4 inline-block text-sm text-teal-800 underline');
    link.href = path;
    link.download = entry.name;
    item.append(link);
    if (['ips.txt', 'domains.txt'].includes(entry.name)) {
      const normalized = node('a', 'Нормализованный список', 'mt-1 inline-block text-sm text-teal-800 underline');
      normalized.href = path + '?normalized=1';
      normalized.download = 'normalized-' + entry.name;
      item.append(normalized);
    }
    $('feed-files').append(item);
  }
  feedButtons();
}

async function refreshFeed() {
  if (feedBusy) return;
  const generation = ++feedGeneration;
  try {
    const result = await api('/feed');
    if (generation === feedGeneration) renderFeed(result, true);
  } catch (error) {
    if (generation === feedGeneration) $('feed-error').textContent = error.message;
  }
}

function resetFeed() {
  feedGeneration++;
  feedBusy = false;
  feedState = null;
  $('feed-settings').reset();
  $('feed-files').replaceChildren();
  $('feed-key-status').textContent = 'Загрузка…';
  $('feed-status').textContent = '';
  $('feed-error').textContent = '';
  $('feed-allow-shrink').checked = false;
  feedButtons();
}

async function runFeedAction(action, waiting) {
  if (feedBusy || !feedState) return;
  const generation = ++feedGeneration;
  feedBusy = true;
  feedButtons();
  $('feed-error').textContent = '';
  $('feed-status').textContent = waiting;
  try {
    const result = await action();
    if (generation !== feedGeneration) return;
    if (result.accessible) $('feed-status').textContent = 'Каталог доступен с сохранённым ключом';
    else renderFeed(result, true);
  } catch (error) {
    if (generation !== feedGeneration) return;
    try {
      const latest = await api('/feed');
      if (generation === feedGeneration) renderFeed(latest);
    } catch { /* Keep the original error visible. */ }
    if (generation === feedGeneration) $('feed-error').textContent = error.message;
  } finally {
    if (generation === feedGeneration) {
      feedBusy = false;
      feedButtons();
    }
  }
}

function saveFeed(removeKey = false) {
  const key = removeKey ? '' : $('feed-key').value;
  const data = {
    revision: feedState.revision, key, remove_key: removeKey,
    interval_hours: removeKey ? 0 : Number($('feed-hours').value)
  };
  void runFeedAction(async () => {
    $('feed-key').value = '';
    return api('/feed', {method: 'PUT', body: JSON.stringify(data)});
  }, 'Сохранение настроек…');
}

$('feed-settings').addEventListener('submit', event => {
  event.preventDefault();
  if (feedState) saveFeed();
});
$('feed-remove').addEventListener('click', () => saveFeed(true));
$('feed-check').addEventListener('click', () => runFeedAction(() => api('/feed/check', {method: 'POST'}), 'Проверка доступа…'));
$('feed-refresh').addEventListener('click', () => {
  const acceptShrink = $('feed-allow-shrink').checked;
  $('feed-allow-shrink').checked = false;
  void runFeedAction(() => api('/feed/refresh', {method: 'POST', body: JSON.stringify({accept_shrink: acceptShrink})}), 'Загрузка и проверка данных…');
});

const feedConsumers = {
  firewall: {file: 'ips.txt', page: 'Межсетевой экран'},
  dns: {file: 'domains.txt', page: 'DNS и DHCP'}
};

function feedDraft(kind) {
  if (kind === 'firewall') return {revision: snapshot?.revision, filter: snapshot?.config.security_feed, dirty};
  return {revision: servicesSnapshot?.revision, filter: servicesSnapshot?.config.dns.security_feed, dirty: servicesDirty};
}

function feedFilterLabel(filter) {
  if (!filter) return 'выключен';
  const count = filter.count ?? filter.values.length;
  const exceptions = Array.isArray(filter.exceptions) ? filter.exceptions.length : filter.exceptions || 0;
  return `Записей ${count.toLocaleString('ru-RU')} · Исключений ${exceptions} · ${filter.sha256.slice(0, 12)}`;
}

function renderFeedConsumers() {
  for (const [kind, consumer] of Object.entries(feedConsumers)) {
    const {revision, filter, dirty: edited} = feedDraft(kind);
    const current = kind === 'firewall' ? firewallState : servicesState;
    const latest = feedState?.entries.find(e => e.name === consumer.file);
    const input = $('feed-' + kind + '-exceptions');
    if (input.dataset.revision !== String(revision)) {
      input.value = (filter?.exceptions || []).join('\n');
      input.dataset.revision = String(revision);
    }
    const draftLabel = revision ? feedFilterLabel(filter) : 'загрузка';
    const editLabel = edited ? ' · Сначала сохраните изменения' : '';
    $('feed-' + kind + '-draft').textContent = 'Черновик · ' + draftLabel + editLabel;
    $(kind + '-feed-draft').textContent = 'Черновик · ' + draftLabel;
    $('feed-' + kind + '-confirmed').textContent = current?.enabled ?
      'Подтверждённый снимок · ' + feedFilterLabel(current.security_feed) : 'Состояние агента недоступно';
    const disabled = feedBusy || !revision || edited;
    $('feed-' + kind + '-stage').disabled = disabled || !latest;
    $('feed-' + kind + '-disable').disabled = disabled || !filter;
  }
}

async function stageFeedConsumer(kind, disable = false) {
  const consumer = feedConsumers[kind];
  const draft = feedDraft(kind);
  const latest = feedState?.entries.find(e => e.name === consumer.file);
  if (draft.dirty || !draft.revision || (!disable && !latest)) return;
  const body = {revision: draft.revision, disable};
  if (!disable) {
    body.sha256 = latest.sha256;
    body.exceptions = $('feed-' + kind + '-exceptions').value.split(/[\s,]+/).filter(Boolean);
  }
  if (feedBusy) return;
  const generation = ++feedGeneration;
  feedBusy = true;
  feedButtons();
  $('feed-error').textContent = '';
  $('feed-status').textContent = 'Сохранение черновика…';
  try {
    const saved = await api('/feed/consumers/' + kind, {method: 'POST', body: JSON.stringify(body)});
    if (generation !== feedGeneration) return;
    const current = feedDraft(kind);
    if (!current.dirty && current.revision === draft.revision) {
      if (kind === 'firewall') {
        snapshot = saved;
        editVersion++;
        $('revision').textContent = saved.revision;
        $('preview-section').hidden = true;
        renderRules();
      } else {
        servicesSnapshot = saved;
        servicesEdit++;
        $('services-preview').hidden = true;
        servicesRender();
      }
    }
    $('feed-status').textContent = 'Черновик сохранён. Для проверки и применения откройте «' + consumer.page + '».';
  } catch (error) {
    if (generation === feedGeneration) {
      if (feedState) renderFeed(feedState);
      $('feed-error').textContent = error.message;
    }
  } finally {
    if (generation === feedGeneration) {
      feedBusy = false;
      feedButtons();
    }
  }
}

for (const kind of Object.keys(feedConsumers)) {
  $('feed-consumer-' + kind).addEventListener('submit', e => {
    e.preventDefault();
    void stageFeedConsumer(kind);
  });
  $('feed-' + kind + '-disable').addEventListener('click', () => stageFeedConsumer(kind, true));
}
