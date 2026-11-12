'use strict';

const [syncOverview, resetOverview] = (() => {
  const widgets = [...$('overview-widgets').children];
  const keys = widgets.map(widget => widget.dataset.widget);
  const select = $('overview-interface');
  const format = new Intl.NumberFormat('ru-RU', {maximumFractionDigits: 1});
  const windowMS = 120_000;
  const sampleMS = 2_000;
  const colors = ['#0f766e', '#1d4ed8'];
  let preferences, account, polling, metricsTimer, runtimeTimer;
  let previous, points = [];

  const enabled = key => !preferences.hidden.includes(key);
  const active = () => isAdmin() && !$('app').hidden && !$('page-overview').hidden && !document.hidden;

  function loadLayout() {
    const stored = {};
    try { Object.assign(stored, JSON.parse(localStorage.getItem(account))); } catch {}
    const order = Array.isArray(stored.order) ? stored.order.filter(key => keys.includes(key)) : [];
    const hidden = Array.isArray(stored.hidden) ? stored.hidden.filter(key => keys.includes(key)) : [];
    preferences = {order: [...new Set([...order, ...keys])], hidden, interface: stored.interface || ''};
    layout();
  }

  function saveLayout() {
    try { localStorage.setItem(account, JSON.stringify(preferences)); } catch {}
  }

  function layout(focus) {
    const controls = preferences.order.map((key, index) => {
      const widget = widgets.find(item => item.dataset.widget === key);
      const title = widget.dataset.title;
      widget.hidden = !enabled(key);
      $('overview-widgets').append(widget);

      const control = node('div', '', 'flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2');
      const label = node('label', '', 'flex flex-1 items-center gap-2');
      const check = node('input', '', 'mt-0! size-4 w-4');
      check.type = 'checkbox';
      check.checked = enabled(key);
      check.addEventListener('change', () => {
        preferences.hidden = check.checked
          ? preferences.hidden.filter(item => item !== key)
          : [...preferences.hidden, key];
        widget.hidden = !check.checked;
        saveLayout();
        stop();
        sync();
      });
      label.append(check, document.createTextNode(title));
      control.append(label);
      for (const [step, arrow, action] of [[-1, '↑', 'Выше'], [1, '↓', 'Ниже']]) {
        const button = node('button', arrow, 'rounded border border-slate-300 px-2 py-0.5 text-sm');
        button.type = 'button';
        button.disabled = index + step < 0 || index + step >= preferences.order.length;
        button.setAttribute('aria-label', title + ' · ' + action);
        button.dataset.move = key + ':' + step;
        button.addEventListener('click', () => {
          const order = preferences.order;
          [order[index], order[index + step]] = [order[index + step], order[index]];
          saveLayout();
          layout(key + ':' + step);
        });
        control.append(button);
      }
      return control;
    });
    $('overview-layout').replaceChildren(...controls);
    if (focus) {
      const button = $('overview-layout').querySelector('[data-move="' + focus + '"]');
      (button.disabled ? button.parentElement.querySelector('input') : button).focus();
    }
  }

  function rateLabel(bits) {
    if (bits == null) return '—';
    for (const [scale, unit] of [[1e9, 'Гбит/с'], [1e6, 'Мбит/с'], [1e3, 'кбит/с'], [1, 'бит/с']]) {
      if (bits >= scale || scale === 1) return format.format(bits / scale) + ' ' + unit;
    }
  }

  function percent(value) {
    return value == null ? '—' : format.format(value) + '%';
  }

  function draw(canvas, fields, max, label) {
    const {width, height} = canvas.getBoundingClientRect();
    if (!width || !height) return;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.scale(ratio, ratio);
    const x0 = 76, x1 = width - 4, y0 = 10, y1 = height - 20;
    if (x1 <= x0) return;
    ctx.font = '11px system-ui';
    ctx.fillStyle = '#64748b';
    ctx.strokeStyle = '#e2e8f0';
    ctx.textBaseline = 'middle';
    for (const fraction of [0, 0.5, 1]) {
      const y = y1 - fraction * (y1 - y0);
      ctx.beginPath();
      ctx.moveTo(x0, y);
      ctx.lineTo(x1, y);
      ctx.stroke();
      ctx.fillText(label(max * fraction), 0, y, x0 - 8);
    }
    ctx.fillText('−2 мин', x0, height - 7);
    ctx.textAlign = 'right';
    ctx.fillText('сейчас', x1, height - 7);

    const last = points.at(-1)?.time ?? 0;
    for (const [index, field] of fields.entries()) {
      ctx.strokeStyle = colors[index];
      ctx.fillStyle = colors[index];
      ctx.lineWidth = 2;
      let previousX, previousY, previousTime;
      for (const point of points) {
        if (point[field] == null) { previousTime = undefined; continue; }
        const x = x1 - (last - point.time) * (x1 - x0) / windowMS;
        const y = y1 - Math.min(point[field] / max, 1) * (y1 - y0);
        ctx.beginPath();
        if (previousTime !== undefined && point.time - previousTime <= 4 * sampleMS) {
          ctx.moveTo(previousX, previousY);
          ctx.lineTo(x, y);
          ctx.stroke();
        } else {
          ctx.arc(x, y, 2, 0, 2 * Math.PI);
          ctx.fill();
        }
        previousX = x;
        previousY = y;
        previousTime = point.time;
      }
    }
  }

  function drawCharts() {
    draw($('overview-system-chart'), ['cpu', 'memory'], 100, percent);
    let peak = 1000;
    for (const point of points) peak = Math.max(peak, point.rx ?? 0, point.tx ?? 0);
    const unit = 10 ** Math.floor(Math.log10(peak));
    draw($('overview-link-chart'), ['rx', 'tx'], Math.ceil(peak / unit) * unit, rateLabel);
  }

  function difference(now, before) {
    const delta = BigInt(now) - BigInt(before);
    return delta >= 0n ? Number(delta) : null;
  }

  function updateMetrics(sample) {
    const names = sample.interfaces.map(link => link.name);
    if (!names.every((name, i) => name === select.options[i]?.value) || names.length !== select.options.length) {
      select.replaceChildren(...names.map(name => new Option(name, name)));
    }
    const name = names.includes(preferences.interface) ? preferences.interface : names.find(item => item !== 'lo') ?? names[0];
    if (select.value !== name) select.value = name ?? '';
    select.disabled = !name;

    const now = sample.uptime_ms;
    if (previous && previous.uptime_ms > now) { previous = null; points = []; }
    const last = points.at(-1);
    if (last?.interface !== name) {
      for (const point of points) { point.rx = null; point.tx = null; }
    }
    const point = {time: now, interface: name, cpu: null, memory: (1 - sample.memory_available / sample.memory_total) * 100, rx: null, tx: null};
    if (previous && now > previous.uptime_ms && now - previous.uptime_ms <= 4 * sampleMS) {
      const total = difference(sample.cpu.total, previous.cpu.total);
      const idle = difference(sample.cpu.idle, previous.cpu.idle);
      if (total > 0 && idle != null && idle <= total) point.cpu = (1 - idle / total) * 100;
      const link = sample.interfaces.find(item => item.name === name);
      const before = previous.interfaces.find(item => item.name === name);
      if (link && before) {
        const perSecond = 8000 / (now - previous.uptime_ms);
        const rx = difference(link.rx_bytes, before.rx_bytes);
        const tx = difference(link.tx_bytes, before.tx_bytes);
        point.rx = rx == null ? null : rx * perSecond;
        point.tx = tx == null ? null : tx * perSecond;
      }
    }
    previous = sample;
    points = points.filter(item => now - item.time < windowMS);
    points.push(point);
    $('overview-cpu').textContent = percent(point.cpu);
    $('overview-memory').textContent = percent(point.memory) + ' · ' + format.format((sample.memory_total - sample.memory_available) / 2**30) + ' ГиБ';
    $('overview-rx').textContent = rateLabel(point.rx);
    $('overview-tx').textContent = rateLabel(point.tx);
    $('overview-uptime').textContent = 'Время работы ' + Math.floor(now / 3600000) + ' ч ' + Math.floor(now / 60000) % 60 + ' мин';
    $('overview-system-note').textContent = point.cpu == null ? 'Собираем замеры…' : 'Последние 2 минуты · шаг 2 с';
    $('overview-link-note').textContent = !name ? 'Интерфейсы недоступны' :
      point.rx == null || point.tx == null ? 'Собираем замеры…' : 'Последние 2 минуты · шаг 2 с';
    drawCharts();
  }

  function clearMetrics(note) {
    previous = null;
    points = [];
    for (const id of ['overview-cpu', 'overview-memory', 'overview-rx', 'overview-tx']) $(id).textContent = '—';
    $('overview-uptime').textContent = '';
    select.disabled = true;
    $('overview-system-note').textContent = note;
    $('overview-link-note').textContent = note;
    drawCharts();
  }

  function renderRows(target, rows) {
    $(target).replaceChildren(...rows.map(([title, detail, page]) => {
      const row = node('li', '', 'flex flex-wrap items-baseline justify-between gap-2 py-2');
      const label = node(page ? 'a' : 'span', title, 'break-all font-medium');
      if (page) { label.href = '#' + page; label.classList.add('text-teal-800', 'hover:underline'); }
      row.append(label, node('span', detail, 'break-all text-xs text-slate-500'));
      return row;
    }));
  }

  function renderServices(data) {
    const rows = [];
    const add = (title, detail, page, condition) => { if (condition) rows.push([title, detail, page]); };
    add('Межсетевой экран', 'nftables', 'firewall', data.firewall?.enabled && (data.firewall.confirmed_revision || data.firewall.pending?.status === 'pending'));
    add('Go DNS', 'Слушатель активен', 'services', data.services?.runtime?.dns_running);
    add('Go DHCP', 'Активных слушателей: ' + data.services?.runtime?.dhcp_running, 'services', data.services?.runtime?.dhcp_running);
    add('FESS', 'Reverse proxy / WAF', 'fess', data.fess?.enabled);
    add('Suricata', data.ids?.runtime?.mode?.toUpperCase() || 'IDS', 'ids', data.ids?.runtime?.running);
    add('WireGuard', 'Интерфейсы подняты', 'wireguard', data.wireguard?.runtime?.some(tunnel => tunnel.up));
    add('OpenVPN', 'Есть запущенные экземпляры', 'openvpn', data.openvpn?.agent?.runtime?.some(instance => instance.running));
    add('IPsec', 'Конфигурация загружена', 'ipsec', data.ipsec?.agent?.runtime?.some(tunnel => tunnel.loaded));
    add('Ранняя фильтрация', 'XDP', 'xdp', data.xdp?.runtime?.length);
    add('Ускорение транзита', 'Flowtable', 'firewall', data.flow?.active);
    add('Захват пакетов', 'Идёт захват', 'capture', data.capture?.sessions?.some(session => session.state === 'running'));
    add('Коллектор трафика', 'conntrack / NFLOG', 'traffic', data.traffic?.agent?.conntrack || data.traffic?.agent?.nflog);
    add('Экспорт трафика', 'ClickHouse', 'traffic', data.traffic?.ready);
    renderRows('overview-running', rows);
    const partial = Object.keys(data).some(key => key !== 'feed' && data[key] === null) ||
      data.openvpn?.agent?.runtime_error || data.ipsec?.agent?.runtime_error || data.wireguard?.runtime_error ||
      data.traffic?.agent_error || data.services?.runtime?.error || data.ids?.runtime?.error || data.xdp?.error || data.fess?.error;
    $('overview-running-note').textContent = partial ? 'Часть служб не предоставила состояние.' :
      rows.length ? '' : 'Активных служб нет.';
  }

  function renderVPN(data) {
    const rows = [];
    const openvpn = data.openvpn?.agent;
    const ipsec = data.ipsec?.agent;
    for (const instance of openvpn?.runtime ?? []) {
      if (!instance.running || instance.mode !== 'server') continue;
      for (const session of instance.sessions ?? []) {
        rows.push([session.username || session.name || 'Клиент', 'OpenVPN · ' + (session.address || instance.interface), 'openvpn']);
      }
    }
    for (const tunnel of ipsec?.runtime ?? []) {
      const config = ipsec.active?.tunnels?.find(item => item.id === tunnel.id);
      for (const session of tunnel.sessions ?? []) {
        rows.push([session.username || session.identity || config?.name || 'Шлюз', 'IKEv2 · ' + (config?.name || 'активная SA'), 'ipsec']);
      }
    }
    const now = Date.now();
    for (const tunnel of data.wireguard?.runtime ?? []) {
      if (!tunnel.up) continue;
      for (const peer of tunnel.peers ?? []) {
        const age = now - Date.parse(peer.last_handshake);
        if (age >= -5000 && age <= 180_000) {
          rows.push([peer.name || peer.id, 'WireGuard · handshake ' + Math.max(0, Math.floor(age / 1000)) + ' с назад', 'wireguard']);
        }
      }
    }
    renderRows('overview-vpn', rows);
    const partial = [data.wireguard, data.openvpn, data.ipsec].some(result => result === null) ||
      openvpn?.runtime_error || ipsec?.runtime_error || data.wireguard?.runtime_error ||
      openvpn?.runtime?.some(instance => instance.sessions_error);
    const note = partial ? 'Часть VPN не предоставила состояние. ' : rows.length ? '' : 'Активных сеансов нет. ';
    $('overview-vpn-note').textContent = note + 'Для WireGuard показаны пиры с handshake за 3 минуты.';
  }

  function renderIOC(feed, ids) {
    const status = $('overview-ioc-status');
    status.textContent = !feed ? 'Данные подписки недоступны' : !feed.success_at ? 'Снимок ещё не загружен' :
      feed.stale ? 'Снимок устарел' : 'Снимок актуален';
    status.classList.toggle('text-amber-800', Boolean(feed?.stale));
    const details = [];
    if (feed?.success_at) details.push(['Последнее обновление', new Date(feed.success_at).toLocaleString('ru-RU')]);
    if (feed) details.push(['Обновление', !feed.has_key ? 'ключ подписки не настроен' :
      feed.interval_hours ? 'каждые ' + feed.interval_hours + ' ч' : 'вручную']);
    for (const [name, label] of [['iocs.json', 'IOC'], ['ips.txt', 'IP/CIDR'], ['domains.txt', 'Домены']]) {
      const entry = feed?.entries?.find(item => item.name === name);
      if (entry) details.push([label, format.format(entry.count)]);
    }
    const activeSnapshot = ids?.runtime?.file_ioc_snapshot;
    const downloadedSnapshot = feed?.entries?.find(item => item.name === 'iocs.json')?.sha256;
    if (activeSnapshot && downloadedSnapshot) details.push(['IOC в Suricata',
      activeSnapshot === downloadedSnapshot ? 'Последний загруженный снимок' : 'Другой снимок']);
    $('overview-ioc-details').replaceChildren(...details.map(([key, value]) => {
      const row = node('div', '', 'flex justify-between gap-3');
      row.append(node('dt', key), node('dd', value, 'text-right'));
      return row;
    }));
    $('overview-ioc-error').textContent = feed?.error ?
      'Последняя попытка ' + new Date(feed.attempt_at).toLocaleString('ru-RU') + ' завершилась ошибкой.' : '';
  }

  async function collectMetrics(signal) {
    try {
      const sample = await api('/metrics', {signal: AbortSignal.any([signal, AbortSignal.timeout(4000)])});
      if (!signal.aborted && active()) updateMetrics(sample);
    } catch (err) {
      if (!signal.aborted && active()) clearMetrics(err.message);
    }
    if (!signal.aborted && active()) metricsTimer = setTimeout(() => collectMetrics(signal), sampleMS);
  }

  async function collectRuntime(signal) {
    const requests = {};
    if (enabled('vpn') || enabled('modules')) Object.assign(requests, {
      wireguard: '/wireguard/state', openvpn: '/openvpn/runtime/state', ipsec: '/ipsec/state'
    });
    if (enabled('modules')) Object.assign(requests, {
      firewall: '/changes/state', services: '/services/state', fess: '/fess/state', ids: '/ids/state',
      xdp: '/xdp/state', flow: '/firewall/flow', capture: '/captures', traffic: '/traffic/status'
    });
    if (enabled('ioc')) Object.assign(requests, {feed: '/feed', ids: '/ids/state'});
    const bounded = AbortSignal.any([signal, AbortSignal.timeout(7000)]);
    const data = Object.fromEntries(await Promise.all(Object.entries(requests).map(async ([key, path]) => {
      return [key, await api(path, {signal: bounded}).catch(() => null)];
    })));
    if (signal.aborted || !active()) return;
    if (enabled('modules')) renderServices(data);
    if (enabled('vpn')) renderVPN(data);
    if (enabled('ioc')) renderIOC(data.feed, data.ids);
    runtimeTimer = setTimeout(() => collectRuntime(signal), 20_000);
  }

  function stop() {
    polling?.abort();
    polling = null;
    clearTimeout(metricsTimer);
    clearTimeout(runtimeTimer);
  }

  function sync() {
    if (!active()) { stop(); return; }
    const key = 'gfw.dashboard.' + currentAccount.user;
    if (account !== key) { account = key; loadLayout(); }
    if (polling) return;
    polling = new AbortController();
    if (enabled('system') || enabled('interface')) void collectMetrics(polling.signal);
    if (enabled('modules') || enabled('vpn') || enabled('ioc')) void collectRuntime(polling.signal);
  }

  select.addEventListener('change', () => {
    preferences.interface = select.value;
    saveLayout();
    for (const point of points) { point.rx = null; point.tx = null; }
    $('overview-rx').textContent = '—';
    $('overview-tx').textContent = '—';
    $('overview-link-note').textContent = 'Собираем замеры…';
    drawCharts();
  });
  const observer = new ResizeObserver(drawCharts);
  observer.observe($('overview-system-chart'));
  observer.observe($('overview-link-chart'));
  document.addEventListener('visibilitychange', sync);
  sync();
  return [sync, () => {
    stop();
    account = null;
    clearMetrics('Собираем замеры…');
    renderRows('overview-running', []);
    renderRows('overview-vpn', []);
    renderIOC(null);
  }];
})();
