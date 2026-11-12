'use strict';

const trafficConfigForm = $('traffic-config');
const trafficSearchForm = $('traffic-search');
const trafficKinds = {new: 'Открытие', update: 'Обновление', destroy: 'Закрытие', rule: 'Срабатывание правила', snapshot: 'Активное соединение'};
const trafficActions = {accept: 'Разрешено', drop: 'Отброшено', reject: 'Отклонено'};
const trafficProtocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 50: 'ESP', 58: 'ICMPv6', 132: 'SCTP'};
const trafficSystemRules = {'@default': 'Блокировка по умолчанию', '@invalid': 'Некорректное состояние'};
let trafficConfigLoaded = false, trafficSession = 0, trafficRequest = 0;

async function refreshTraffic() {
  const session = trafficSession;
  try {
    const state = await api('/traffic/status');
    if (session !== trafficSession) return;
    if (!trafficConfigLoaded) {
      for (const field of ['url', 'database', 'user']) {
        trafficConfigForm.elements[field].value = state.config[field] || (field === 'database' ? 'default' : '');
      }
      trafficConfigLoaded = true;
    }
    const agent = state.agent;
    const parts = [state.config.url ? (state.error ? 'Ошибка доставки' : state.ready ? 'ClickHouse подключён' : 'Подключение к ClickHouse') : 'ClickHouse не настроен'];
    if (!state.agent_error) {
      parts.push(`conntrack ${agent.conntrack ? 'активен' : 'неактивен'}`, `NFLOG ${agent.nflog ? 'активен' : 'неактивен'}`);
      if (agent.nflog && !agent.nflog_conntrack) parts.push('NFLOG передаёт адреса и порты');
      parts.push(`Учёт пакетов и байтов ${agent.accounting ? 'включён' : 'выключен'}`);
      parts.push(`В очереди ${agent.queued}`, `Вытеснено ${agent.evicted}`, `Потери коллектора ${agent.lost}`);
      if (agent.rate_limited != null) parts.push(`Пропущено по лимиту ${agent.rate_limited}`);
      if (agent.incomplete_snapshots) parts.push(`Неполные снимки ${agent.incomplete_snapshots}`);
      if (agent.oldest_ms) parts.push(`Старейшее событие ${new Date(agent.oldest_ms).toLocaleString('ru-RU')}`);
    }
    if (Date.parse(state.last_write) > 0) parts.push(`Последняя запись ${new Date(state.last_write).toLocaleString('ru-RU')}`);
    $('traffic-status').textContent = parts.join(' · ');
    $('traffic-health-error').textContent = [state.agent_error, agent.error, state.error].filter(Boolean).join(' · ');
  } catch (err) {
    if (session === trafficSession) $('traffic-health-error').textContent = err.message;
  }
}

function trafficEndpoint(ip, port) {
  if (!ip) return '—';
  return port ? `${ip.includes(':') ? '[' + ip + ']' : ip}:${port}` : ip;
}

function trafficRow(event) {
  const row = node('tr', '');
  const time = node('td', new Date(event.at_ms).toLocaleString('ru-RU'), 'p-3 align-top whitespace-nowrap');
  time.append(node('div', event.device, 'text-xs text-slate-500'));
  const kind = node('td', trafficKinds[event.kind] || event.kind, 'p-3 align-top');
  if (event.action) kind.append(node('div', trafficActions[event.action] || event.action, 'text-xs text-slate-500'));
  const addresses = node('td', `${trafficProtocols[event.proto] || event.proto} · ${trafficEndpoint(event.src, event.sport)} → ${trafficEndpoint(event.dst, event.dport)}`, 'p-3 align-top font-mono text-xs');
  if (event.reply_src) addresses.append(node('div', `Ответ · ${trafficEndpoint(event.reply_src, event.reply_sport)} → ${trafficEndpoint(event.reply_dst, event.reply_dport)}`, 'mt-1 text-slate-500'));
  if (event.nat) addresses.append(node('div', 'NAT', 'mt-1 text-slate-500'));
  const rule = node('td', '', 'p-3 align-top');
  if (event.rule) {
    const current = !dirty && snapshot?.revision === event.revision && snapshot.config.rules.find(rule => rule.id === event.rule);
    const label = current?.name || trafficSystemRules[event.rule] ||
      (event.rule.startsWith('@feed-') ? 'Блокировка по Security Feed' : event.rule);
    const filter = node('button', label, 'break-all text-left text-xs font-medium text-teal-800 hover:underline');
    filter.type = 'button';
    filter.title = `Поиск по правилу ${event.rule}`;
    filter.addEventListener('click', () => filterTraffic({rule: event.rule}));
    rule.append(filter, node('div', `Ревизия ${event.revision} · ${directions[event.direction] || event.direction}`, 'text-xs text-slate-500'));
  }
  if (event.flow_id) {
    const filter = node('button', event.flow_id, 'mt-1 block break-all text-left font-mono text-xs text-teal-800 hover:underline');
    filter.type = 'button';
    filter.title = 'Показать события этого соединения';
    filter.addEventListener('click', () => filterTraffic({flow_id: event.flow_id}));
    rule.append(filter);
  } else if (event.kind === 'rule' && event.src) {
    const filter = node('button', 'Соединения по адресу и порту', 'mt-1 block text-left text-xs text-teal-800 hover:underline');
    filter.type = 'button';
    filter.addEventListener('click', () => filterTraffic({
      kind: 'flow', ip: event.src, port: event.dport || '', proto: event.proto, device: event.device
    }));
    rule.append(filter);
  }
  if (!event.rule && !event.flow_id) rule.textContent = '—';
  const accounting = node('td', '—', 'p-3 align-top whitespace-nowrap text-xs');
  if (event.packets != null || event.bytes != null) accounting.textContent = `${event.packets ?? '—'} / ${event.bytes ?? '—'}`;
  if (event.reply_packets != null || event.reply_bytes != null) accounting.append(node('div', `Ответ · ${event.reply_packets ?? '—'} / ${event.reply_bytes ?? '—'}`, 'mt-1 text-slate-500'));
  row.append(time, kind, addresses, rule, accounting);
  return row;
}

function filterTraffic(filters) {
  const hours = trafficSearchForm.elements.hours.value;
  trafficSearchForm.reset();
  trafficSearchForm.elements.hours.value = hours;
  for (const [field, value] of Object.entries(filters)) trafficSearchForm.elements[field].value = value;
  void searchTraffic();
}

async function searchTraffic() {
  const request = ++trafficRequest;
  const query = new URLSearchParams();
  for (const [field, raw] of new FormData(trafficSearchForm)) {
    if (raw.trim()) query.set(field, raw.trim());
  }
  $('traffic-results-note').textContent = 'Поиск…';
  $('traffic-results').hidden = true;
  try {
    const events = await api('/traffic/events?' + query);
    if (request !== trafficRequest) return;
    $('traffic-rows').replaceChildren(...events.map(trafficRow));
    $('traffic-results').hidden = events.length === 0;
    $('traffic-results-note').textContent = events.length === 250 ? 'Показаны 250 последних событий. Уточните фильтры, чтобы сузить поиск.' :
      events.length ? `Событий найдено: ${events.length}` : 'Событий по этим фильтрам нет.';
  } catch (err) {
    if (request === trafficRequest) $('traffic-results-note').textContent = err.message;
  }
}

function resetTraffic() {
  trafficSession++;
  trafficConfigLoaded = false;
  trafficConfigForm.reset();
  trafficSearchForm.reset();
  for (const id of ['traffic-status', 'traffic-health-error', 'traffic-config-note', 'traffic-rows']) $(id).replaceChildren();
}

$('traffic-refresh').addEventListener('click', refreshTraffic);
trafficSearchForm.addEventListener('submit', event => {
  event.preventDefault();
  void searchTraffic();
});
trafficSearchForm.addEventListener('reset', () => {
  trafficRequest++;
  $('traffic-results').hidden = true;
  $('traffic-results-note').textContent = 'Задайте фильтры и нажмите «Найти».';
});
trafficConfigForm.addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.submitter;
  const session = trafficSession;
  button.disabled = true;
  try {
    const config = Object.fromEntries(new FormData(trafficConfigForm));
    config.url = config.url.trim();
    await api('/traffic/config', {method: 'PUT', body: JSON.stringify(config)});
    if (session !== trafficSession) return;
    trafficConfigForm.elements.password.value = '';
    $('traffic-config-note').textContent = config.url ? 'Настройки сохранены. Агент доставки проверит подключение.' : 'Доставка в ClickHouse отключена.';
    trafficConfigLoaded = false;
    trafficRequest++;
    $('traffic-results').hidden = true;
    $('traffic-results-note').textContent = 'Задайте фильтры и нажмите «Найти».';
    await refreshTraffic();
  } catch (err) {
    if (session === trafficSession) $('traffic-config-note').textContent = err.message;
  } finally {
    button.disabled = false;
  }
});
