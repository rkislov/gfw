'use strict';
const $ = id => document.getElementById(id);
let csrf = '', snapshot = null, dirty = false, editVersion = 0, firewallState = null, changeBusy = false;
let currentAccount = null;
const isAdmin = () => currentAccount?.role === 'admin';
const directions = {input: 'К устройству', forward: 'Через устройство', output: 'От устройства'};
const titles = {
  users: ['Пользователи и вход', 'Учётные записи, источники паролей и назначения VPN.'],
  sysctl: ['Производительность', 'Параметры очередей и conntrack по ресурсам Linux-узла.'],
  portal: ['Личный кабинет', 'Второй фактор и персональные профили VPN.'],
  overview: ['Обзор системы', 'Состояние устройства и последние изменения конфигурации.'],
  network: ['Сетевые интерфейсы', 'Порты и IP-адреса управляемого узла.'],
  firewall: ['Межсетевой экран', 'Упорядоченные правила и компиляция черновика в nftables.'],
  services: ['DNS и DHCP', 'Службы разрешения имён и выдачи адресов в составе GFW.'],
  ipsec: ['IPsec / IKEv2', 'Туннели между шлюзами, сертификаты CA и журнал IKE.'],
  openvpn: ['OpenVPN VPN', 'Сервер и клиент, сертификаты, CRL, журналы и экспорт .ovpn.'],
  wireguard: ['WireGuard VPN', 'Туннели, peers и состояние соединений.'],
  pki: ['Сертификаты и ACME', 'Общий центр управления сертификатами GFW.'],
  fess: ['Сайты и WAF', 'Маршруты, сертификаты и правила FESS.'],
  ids: ['Обнаружение угроз', 'Suricata IDS/IPS, состояние и журнал обнаружений.'],
  feed: ['Подписка Security Feed', 'Загрузка IP-адресов, доменов и индикаторов угроз.'],
  traffic: ['Журнал трафика', 'Соединения conntrack и срабатывания правил межсетевого экрана.'],
  xdp: ['Ранняя фильтрация XDP', 'Блокировки по IP/CIDR на входе WAN до обработки межсетевым экраном.'],
  capture: ['Захват пакетов', 'Выберите интерфейс и фильтр, затем скачайте PCAP.'],
  audit: ['Аудит изменений', 'Административные события и отправка в SIEM.']
};
function node(tag, text, classes = '') { const n = document.createElement(tag); n.textContent = text; n.className = classes; return n; }
function message(text) { $('message-text').textContent = text; $('message').hidden = false; }
$('dismiss-message').addEventListener('click', () => { $('message').hidden = true; });
$('dismiss-default-password').addEventListener('click', () => { $('default-password-notice').hidden = true; });
function markDirty() { dirty = true; editVersion++; if (typeof renderFeedConsumers === "function") renderFeedConsumers(); $('dirty').textContent = 'Есть несохранённые изменения'; $('preview-section').hidden = true; updateApplyButtons(); }
async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (csrf) headers['X-GFW-CSRF'] = csrf;
  const response = await fetch('/api/v1' + path, { ...options, headers, credentials: 'same-origin' });
  let data;
  try { data = await response.json(); } catch { throw new Error('Сервер вернул некорректный ответ'); }
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/portal/totp/')) {
      $('login').hidden = false;
      $('app').hidden = true;
      resetSIEM();
      if (typeof resetOverview === 'function') resetOverview();
    }
    throw new Error(data.error || 'Ошибка запроса');
  }
  return data;
}
function page(name) {
  if (currentAccount && !isAdmin()) name = 'portal';
  if (!Object.hasOwn(titles, name) || name === 'portal' && !currentAccount?.personal) name = 'overview';
  for (const el of document.querySelectorAll('.page')) el.hidden = el.id !== 'page-' + name;
  for (const el of document.querySelectorAll('.nav')) {
    const active = el.dataset.page === name;
    el.classList.toggle('bg-slate-800', active); el.classList.toggle('text-white', active);
    if (active) el.setAttribute('aria-current', 'page'); else el.removeAttribute('aria-current');
  }
  if (['wireguard', 'openvpn', 'ipsec'].includes(name)) $('vpn-menu').open = true;
  if (name === 'fess' && typeof refreshFESS === 'function') void refreshFESS();
  if (name === 'ids' && typeof refreshIDS === 'function') void refreshIDS();
  if (name === 'firewall' && typeof refreshFlow === 'function') void refreshFlow();
  if (name === 'xdp' && typeof refreshXDP === 'function') void refreshXDP();
  if (name === 'capture' && typeof refreshCapture === 'function') void refreshCapture(true);
  if (name === 'traffic' && typeof refreshTraffic === 'function') void refreshTraffic();
  if (name === 'feed' && typeof refreshFeed === 'function') void refreshFeed();
  if (name === 'portal') void refreshPortal();
  if (name === 'audit') { void refreshSIEM(); void refreshAudit(); }
  if (name === 'users') void refreshIdentityUsers();
  if (name === 'sysctl') void refreshSysctl();
  if (name === 'ipsec' && typeof refreshIPsec === 'function') void refreshIPsec();
  $('page-title').textContent = titles[name][0]; $('page-description').textContent = titles[name][1];
  if (typeof syncOverview === 'function') syncOverview();
}
window.addEventListener('hashchange', () => page(location.hash.slice(1)));
for (const el of document.querySelectorAll('.nav')) el.addEventListener('click', () => { location.hash = el.dataset.page; });
function vpnDisconnectButton(protocol, profileID, sessionID, user, reload) {
  const button = node('button', 'Отключить сеанс', 'text-sm text-red-700 disabled:opacity-40');
  button.type = 'button';
  button.setAttribute('aria-label', `Отключить сеанс ${user} #${sessionID}`);
  button.addEventListener('click', async () => {
    if (!window.confirm(`Завершить сеанс ${user} #${sessionID}? При сохранённом доступе клиент сможет подключиться снова.`)) return;
    button.disabled = true;
    try {
      await api(`/vpn/${protocol}/disconnect`, {
        method: 'POST', body: JSON.stringify({ profile_id: profileID, session_id: sessionID, user })
      });
      message(`Сеанс ${user} завершён.`);
    } catch (err) {
      message(err.message);
    } finally {
      await reload();
      button.disabled = false;
    }
  });
  return button;
}

function renderRules() {
  if (typeof renderFlowDraft === 'function') renderFlowDraft();
  if (typeof renderFeedConsumers === "function") renderFeedConsumers();
  if (typeof renderPolicyObjects === "function") renderPolicyObjects();
  $('rules').replaceChildren();
  const rules = snapshot.config.rules;
  if (!rules.length) { const row = node('tr', ''); const td = node('td', 'Правил пока нет. Добавьте первое правило ниже.', 'p-6 text-slate-500'); td.colSpan = 6; row.append(td); $('rules').append(row); }
  rules.forEach((r, i) => {
    const tr = node('tr', '');
    const name = node('td', '', 'p-4');
    const toggle = node('button', r.name, r.enabled ? 'font-medium text-teal-800' : 'line-through text-slate-400');
    toggle.title = 'Включить или выключить правило';
    toggle.addEventListener('click', () => { r.enabled = !r.enabled; markDirty(); renderRules(); }); name.append(toggle);
    if (r.fast_path || r.log_required) name.append(node('div', r.fast_path ? 'Ускорение разрешено' : 'Обязательное журналирование', 'mt-1 text-xs text-slate-500'));
    tr.append(name, node('td', directions[r.chain] || r.chain, 'p-4 text-xs text-slate-500'), node('td', typeof policyRuleAddresses === 'function' ? policyRuleAddresses(r) : `${r.source || 'Любой'} → ${r.destination || 'Любой'}`, 'p-4 font-mono text-xs'), node('td', typeof policyRuleService === 'function' ? policyRuleService(r) : `${r.protocol.toUpperCase()}${r.destination_port ? ':' + r.destination_port : ''}`, 'p-4 font-mono text-xs'), node('td', ({accept:'Разрешить',drop:'Отбросить',reject:'Отклонить'})[r.action] || r.action, 'p-4 text-xs font-medium'));
    const actions = node('td', '', 'p-4 whitespace-nowrap');
    for (const [label, handler, disabled] of [
      ['Изменить', () => { if (typeof editPolicyRule === 'function') editPolicyRule(r); }, false],
      ['↑', () => { [rules[i - 1], rules[i]] = [rules[i], rules[i - 1]]; }, i === 0],
      ['↓', () => { [rules[i + 1], rules[i]] = [rules[i], rules[i + 1]]; }, i === rules.length - 1],
      ['Удалить', () => rules.splice(i, 1), false]
    ]) { const b = node('button', label, 'mr-2 text-xs text-slate-500 hover:text-red-700 disabled:opacity-30'); b.disabled = disabled; b.setAttribute('aria-label', label + ': ' + r.name); b.addEventListener('click', () => { handler(); if (label !== 'Изменить') { markDirty(); renderRules(); } }); actions.append(b); }
    const journal = node('button', 'Журнал', 'text-xs text-teal-800 hover:underline');
    journal.setAttribute('aria-label', 'Журнал правила «' + r.name + '»');
    journal.addEventListener('click', () => { location.hash = 'traffic'; filterTraffic({rule: r.id}); });
    actions.append(journal);
    tr.append(actions); $('rules').append(tr);
  });
}
const siemForm = $('siem-form');
let siemRevision = 0;
let siemDirty = false;

function resetSIEM() {
  siemRevision = 0;
  siemDirty = false;
  siemForm.reset();
  $('siem-test').disabled = true;
  $('siem-traffic-status').textContent = '';
}

function siemTransport() {
  siemForm.elements.ca_pem.disabled = siemForm.elements.transport.value !== 'tls';
}

async function refreshSIEM() {
  const status = $('siem-status');
  const account = currentAccount;
  try {
    const cfg = await api('/siem');
    if (account !== currentAccount || $('app').hidden) return;
    if (!siemDirty) {
      siemRevision = cfg.revision;
      siemForm.elements.address.value = cfg.address;
      siemForm.elements.transport.value = cfg.transport;
      siemForm.elements.ca_pem.value = cfg.ca_pem;
      siemForm.elements.enabled.checked = cfg.enabled;
      const filter = cfg.traffic || {};
      for (const source of ['conntrack', 'nflog']) {
        for (const checkbox of siemForm.querySelectorAll(`[name="${source}"]`)) {
          checkbox.checked = (filter[source] || []).includes(checkbox.value);
        }
      }
      siemForm.elements.traffic_ip.value = filter.ip || '';
      siemForm.elements.traffic_port.value = filter.port || '';
      siemForm.elements.traffic_protocol.value = filter.protocol ?? '';
      siemForm.elements.traffic_rule.value = filter.rule || '';
      siemForm.elements.traffic_direction.value = filter.direction || '';
      siemTransport();
    }
    $('siem-test').disabled = !cfg.address || siemDirty;
    status.textContent = cfg.delivery_error ? `Доставка ожидает повтора. ${cfg.delivery_error}`
      : cfg.enabled ? cfg.last_sent ? `Последняя отправка · ${new Date(cfg.last_sent).toLocaleString('ru-RU')}` : 'Ожидает первой отправки.'
        : 'Отправка выключена.';
    const traffic = cfg.traffic_stats;
    $('siem-traffic-status').textContent = traffic
      ? [`Трафик в очереди SIEM · ${traffic.queued}`, `Вытеснено · ${traffic.evicted}`,
        traffic.last_sent && `Последняя отправка трафика · ${new Date(traffic.last_sent).toLocaleString('ru-RU')}`,
        cfg.traffic_error && `Доставка ожидает повтора · ${cfg.traffic_error}`, cfg.traffic_queue_error].filter(Boolean).join('. ')
      : '';
  } catch (err) {
    status.textContent = err.message;
  }
}

siemForm.addEventListener('input', () => {
  siemDirty = true;
  $('siem-test').disabled = true;
  siemTransport();
});
siemForm.addEventListener('submit', async event => {
  event.preventDefault();
  if (!siemRevision) return;
  const submit = event.submitter;
  submit.disabled = true;
  const { address, transport, ca_pem, enabled, traffic_ip, traffic_port, traffic_protocol, traffic_rule, traffic_direction } = siemForm.elements;
  const form = new FormData(siemForm);
  try {
    await api('/siem', { method: 'PUT', body: JSON.stringify({
      revision: siemRevision, enabled: enabled.checked, address: address.value,
      transport: transport.value, ca_pem: ca_pem.disabled ? '' : ca_pem.value,
      traffic: {
        conntrack: form.getAll('conntrack'), nflog: form.getAll('nflog'),
        ip: traffic_ip.value.trim(), port: Number(traffic_port.value),
        protocol: traffic_protocol.value === '' ? null : Number(traffic_protocol.value),
        rule: traffic_rule.value.trim(), direction: traffic_direction.value
      }
    }) });
    siemDirty = false;
    await refreshSIEM();
    message('Настройки SIEM сохранены.');
  } catch (err) {
    message(err.message);
  } finally {
    submit.disabled = false;
  }
});
$('siem-test').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api('/siem/test', { method: 'POST' });
    message('Тестовое CEF-событие отправлено. Проверьте приём в SIEM.');
  } catch (err) {
    message(err.message);
  } finally {
    button.disabled = siemDirty;
  }
});

function renderAudit(audit) {
  const auditRows = audit.map(event => {
    const row = node('div', '', 'flex flex-wrap justify-between gap-3 p-4 text-sm');
    const disconnect = /^vpn\.disconnect\.(openvpn|ipsec)\.(request|success|failed):([a-f0-9]+):(\d+):(.+)$/.exec(event.action);
    let action = event.action === 'policy.draft.save' ? 'Сохранён черновик' : event.action;
    if (disconnect) {
      const [, protocol, result, profile, id, user] = disconnect;
      const labels = {request: 'Запрошено отключение', success: 'Сеанс отключён', failed: 'Отключение не подтверждено'};
      action = `${labels[result]} · ${protocol === 'openvpn' ? 'OpenVPN' : 'IPsec'} · ${user} · #${id} · профиль ${profile}`;
    }
    row.append(
      node('span', event.revision ? `${action} · ревизия ${event.revision}` : action, 'font-medium'),
      node('span', `${event.actor} · ${new Date(event.at).toLocaleString('ru-RU')}`, 'text-slate-500 text-xs')
    );
    return row;
  });
  if (!auditRows.length) auditRows.push(node('p', 'Изменений конфигурации ещё нет.', 'p-5 text-sm text-slate-500'));
  $('audit').replaceChildren(...auditRows);
  $('overview-audit').replaceChildren(...auditRows.slice(0, 4).map(row => row.cloneNode(true)));
}

async function refreshAudit() {
  try {
    renderAudit(await api('/audit'));
  } catch (err) {
    message(err.message);
  }
}

async function refresh() {
  $('message').hidden = true;
  if (!isAdmin() || location.hash === '#portal' && currentAccount?.personal) return refreshPortal();
  if (location.hash === '#users') return refreshIdentityUsers();
  if (location.hash === '#sysctl') return refreshSysctl();
  if (location.hash === '#firewall' && typeof refreshFlow === 'function') void refreshFlow();
  if (location.hash === '#xdp' && typeof refreshXDP === 'function') void refreshXDP();
  if (location.hash === '#capture' && typeof refreshCapture === 'function') void refreshCapture(true);
  if (location.hash === '#traffic' && typeof refreshTraffic === 'function') void refreshTraffic();
  if (location.hash === '#ids' && typeof refreshIDS === 'function') void refreshIDS();
  if (location.hash === '#feed' && typeof refreshFeed === 'function') void refreshFeed();
  if (typeof refreshIPsec === 'function') void refreshIPsec();
  const [status, links, audit, config] = await Promise.all([api('/status'), api('/interfaces').catch(e => { message(e.message); return null; }), api('/audit'), dirty ? Promise.resolve(snapshot) : api('/config')]);
  snapshot = config; $('platform').textContent = status.os + ' / ' + status.arch;
  $('gfw-version').textContent = status.version;
  $('revision').textContent = config.revision;
  $('interface-count').textContent = links === null ? 'Недоступно' : links.length;
  $('inventory-source').textContent = status.inventory_source === 'agent' ? 'Источник: локальный gfw-agent через Unix-сокет.' : 'Источник: интерфейсы компьютера, на котором запущен gfwd.';
  $('interfaces').replaceChildren();
  for (const link of links || []) {
    const tr = node('tr', '');
    const addresses = node('td', '', 'p-4 text-xs font-mono'); for (const address of link.addresses) addresses.append(node('div', address, 'mb-1'));
    tr.append(node('td', link.name + (link.loopback ? ' · loopback' : ''), 'p-4 font-medium'), node('td', link.up ? 'UP' : 'DOWN', 'p-4 text-xs ' + (link.up ? 'text-teal-700' : 'text-slate-400')), addresses, node('td', link.mtu, 'p-4 text-slate-500'), node('td', link.mac || '—', 'p-4 font-mono text-xs text-slate-500')); $('interfaces').append(tr);
  }
  if (links === null) { const tr = node('tr', ''); const td = node('td', 'Инвентаризация недоступна. Проверьте подключение к агенту.', 'p-5 text-red-700'); td.colSpan = 5; tr.append(td); $('interfaces').append(tr); }
  renderAudit(audit);
  renderRules();
  await pollChanges();
  if (typeof refreshNetwork === "function") await refreshNetwork();
  if (typeof refreshServices === "function") await refreshServices();
 if (typeof refreshPKI === "function") await refreshPKI();
 if (typeof refreshWireGuard === "function") await refreshWireGuard();
 if (typeof refreshOpenVPN === "function") await refreshOpenVPN();
}
async function enter() {
  const me = await api('/auth/me');
  csrf = me.csrf;
  currentAccount = me;
  $('default-password-notice').hidden = !me.default_password;
  $('current-account').textContent = me.user;
  $('platform').textContent = isAdmin() ? 'GFW' : 'Личный кабинет';
  for (const el of document.querySelectorAll('.nav')) el.hidden = el.dataset.page === 'portal' ? !me.personal : !isAdmin();
  $('vpn-menu').hidden = !isAdmin();
  $('login').hidden = true;
  $('app').hidden = false;
  page(location.hash.slice(1));
  if (isAdmin()) await refresh();
}
$('login-form').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.submitter || e.currentTarget.querySelector('button'); button.disabled = true; $('login-error').textContent = '';
  try { await api('/auth/login', { method: 'POST', body: JSON.stringify({ token: $('token').value }) }); $('token').value = ''; await enter(); }
  catch (err) { $('login-error').textContent = err.message; }
  finally { button.disabled = false; }
});
$('refresh').addEventListener('click', async e => { e.currentTarget.disabled = true; try { await refresh(); } catch (err) { message(err.message); } finally { $('refresh').disabled = false; } });
$('logout').addEventListener('click', async () => { try { await api('/auth/logout', { method: 'POST', body: '{}' }); csrf = ''; currentAccount = null; resetSIEM(); if (typeof resetOverview === 'function') resetOverview(); $('message').hidden = true; resetPortal(); if (typeof resetFlow === 'function') resetFlow(); if (typeof resetXDP === 'function') resetXDP(); if (typeof resetCapture === 'function') resetCapture(); if (typeof resetTraffic === 'function') resetTraffic(); if (typeof resetFeed === 'function') resetFeed(); if (typeof resetIDS === 'function') resetIDS(); if (typeof resetFESS === 'function') resetFESS(); snapshot = null; dirty = false; if (typeof resetNetwork === 'function') resetNetwork(); if (typeof resetServices === 'function') resetServices(); if (typeof resetPKI === 'function') resetPKI(); if (typeof resetWireGuard === 'function') resetWireGuard(); if (typeof resetOpenVPN === 'function') resetOpenVPN(); $('dirty').textContent = 'Нет несохранённых изменений'; $('login').hidden = false; $('app').hidden = true; } catch (err) { message(err.message); } });
$('rule-form').addEventListener('submit', e => {
  e.preventDefault(); const f = new FormData(e.target);
  const rule = Object.fromEntries(f); rule.id = rule.id || crypto.randomUUID(); rule.source = rule.source || ''; rule.destination = rule.destination || ''; rule.protocol = rule.service ? 'any' : (rule.protocol || 'any'); rule.destination_port = rule.service ? 0 : Number(rule.destination_port || 0);
  rule.fast_path = rule.flow_policy === 'fast';
  rule.log_required = rule.flow_policy === 'required';
  delete rule.flow_policy;
  const existing = snapshot.config.rules.findIndex(r => r.id === rule.id); rule.enabled = existing >= 0 ? snapshot.config.rules[existing].enabled : true;
  if (existing >= 0) snapshot.config.rules[existing] = rule; else snapshot.config.rules.push(rule); markDirty(); e.target.reset(); if (typeof syncRuleForm === 'function') syncRuleForm(); renderRules();
});
$('save').addEventListener('click', async () => {
  const controls = [...$('page-firewall').querySelectorAll('button, input, select')].map(el => [el, el.disabled]);
  for (const [el] of controls) el.disabled = true;
  try { snapshot = await api('/config', { method: 'PUT', headers: { 'If-Match': JSON.stringify(String(snapshot.revision)) }, body: JSON.stringify(snapshot.config) }); dirty = false; $('dirty').textContent = 'Нет несохранённых изменений'; $('revision').textContent = snapshot.revision; await refresh(); message('Черновик сохранён. Настройки сети не изменены.'); }
  catch (err) { message(err.message + (err.message.includes('ревизия') ? ' Черновик оставлен в браузере; скопируйте предпросмотр перед перезагрузкой.' : '')); }
  finally { for (const [el, disabled] of controls) if (el.isConnected) el.disabled = disabled; updateApplyButtons(); }
});
$('preview').addEventListener('click', async () => {
  const version = editVersion;
  try { const plan = await api('/changes/plan', { method: 'POST', body: JSON.stringify(snapshot.config) }); if (version !== editVersion) return; $('nftables').textContent = [plan.nftables, plan.flow_nftables].filter(Boolean).join('\n'); $('warnings').replaceChildren(...plan.warnings.map(x => node('li', x))); $('preview-section').hidden = false; }
  catch (err) { message(err.message); }
});
window.addEventListener('beforeunload', e => { if (dirty || (typeof networkDirty !== 'undefined' && networkDirty)) { e.preventDefault(); e.returnValue = ''; } });
enter().catch(err => { if ($('app').hidden === false) message(err.message); });

const changeLabels = {applying: 'Применение', pending: 'Ожидается подтверждение', confirmed: 'Подтверждено', rolled_back: 'Выполнен откат', rolling_back: 'Выполняется откат', rollback_failed: 'Ошибка отката — агент повторяет попытку'};
function updateApplyButtons() {
  $('apply').disabled = changeBusy || dirty || !firewallState?.enabled || !!firewallState?.pending;
  $('confirm-change').disabled = changeBusy || ['network','services','wireguard','openvpn','ipsec','ids','xdp'].includes(firewallState?.pending?.kind) || firewallState?.pending?.status !== 'pending';
  $('rollback-change').disabled = changeBusy || !firewallState?.pending;
}
function updateCountdown() {
  const p = firewallState?.pending;
  if (!p) return;
  const seconds = Math.max(0, Math.ceil((Date.parse(p.deadline) - Date.now()) / 1000));
  $('countdown').textContent = p.status === 'pending' ? (seconds > 0 ? `До автоматического отката: ${seconds} сек.` : 'Срок истёк. Ожидается результат отката от агента.') : (changeLabels[p.status] || p.status);
  if (seconds === 0) $('confirm-change').disabled = true;
}
function renderChanges(state) {
  firewallState = state;
  if (typeof renderFeedConsumers === "function") renderFeedConsumers();
  $('device-mode').textContent = state.enabled ? 'Агент подключён' : 'Предпросмотр';
  $('device-mode-detail').textContent = state.enabled ? `Подтверждённая ревизия: ${state.confirmed_revision || 'ещё нет'}` : 'Применение на этом узле отключено';
  $('apply-status').textContent = state.enabled ? `Подтверждённая ревизия: ${state.confirmed_revision || 'ещё нет'}. Применяется только сохранённый черновик.` : 'Нужен Linux-агент с включённым управлением nftables. Локальный предпросмотр доступен.';
  $('anti-lockout').textContent = state.enabled ? `Системное правило anti-lockout: доступ к панели через ${state.safety.lan_interface}, TCP ${state.safety.management_port}. Защищены запросы и ответы; пользовательские правила его не отменяют.` : '';
  $('pending-change').hidden = !state.pending;
  $('confirm-change').hidden = ['network','services','wireguard','openvpn','ipsec','ids','xdp'].includes(state.pending?.kind);
  $('rollback-change').hidden = ['network','services','wireguard','openvpn','ipsec','ids','xdp'].includes(state.pending?.kind);
  if (state.pending) $('pending-description').textContent = `${state.pending.kind === "xdp" ? "Изменение XDP — откройте «Ранняя фильтрация XDP». " : state.pending.kind === "ids" ? "Изменение IDS/IPS — откройте «Обнаружение угроз». " : state.pending.kind === "ipsec" ? "Изменение IPsec — откройте VPN → IPsec. " : state.pending.kind === "openvpn" ? "Изменение OpenVPN — откройте OpenVPN. " : state.pending.kind === "wireguard" ? "Изменение VPN — откройте WireGuard. " : state.pending.kind === "services" ? "Изменение DNS/DHCP — откройте раздел сервисов. " : state.pending.kind === "network" ? "Изменение сети — откройте раздел интерфейсов. " : ""}${changeLabels[state.pending.status] || state.pending.status} · ревизия ${state.pending.revision} · ${state.pending.id}${state.pending.error ? ' · ' + state.pending.error : ''}`;
  $('change-history').replaceChildren(...state.history.slice(-5).reverse().map(r => node('p', `${changeLabels[r.status] || r.status} · ревизия ${r.revision} · ${new Date(r.created_at).toLocaleString('ru-RU')}${r.error ? ' · ' + r.error : ''}`)));
  updateApplyButtons(); updateCountdown();
}
async function pollChanges() {
  if (!isAdmin() || $('app').hidden) return;
  try { renderChanges(await api('/changes/state')); }
  catch (err) { firewallState = null; if (typeof renderFeedConsumers === "function") renderFeedConsumers(); updateApplyButtons(); $('apply-status').textContent = err.message + '. Если изменение уже применено, таймер отката продолжает работать в агенте.'; $('countdown').textContent = 'Нет связи с агентом. Состояние правил не подтверждено.'; }
}
$('apply').addEventListener('click', async () => {
  const timeout = Number($('confirm-timeout').value);
  if (!Number.isInteger(timeout) || timeout < 30 || timeout > 600) { message('Укажите время подтверждения от 30 до 600 секунд.'); return; }
  if (dirty) { message('Сначала сохраните черновик.'); return; }
  changeBusy = true; updateApplyButtons();
  try { await api('/changes/apply', {method: 'POST', body: JSON.stringify({id: crypto.randomUUID(), revision: snapshot.revision, timeout_seconds: timeout})}); message('Правила применены временно. Проверьте доступ и подтвердите изменение.'); }
  catch (err) { message(err.message); }
  finally { changeBusy = false; await pollChanges(); }
});
for (const [button, action] of [['confirm-change', 'confirm'], ['rollback-change', 'rollback']]) {
  $(button).addEventListener('click', async () => {
    const id = firewallState?.pending?.id; if (!id) return;
    changeBusy = true; updateApplyButtons();
    try { await api(`/changes/${encodeURIComponent(id)}/${action}`, {method: 'POST', body: '{}'}); message(action === 'confirm' ? 'Правила подтверждены и будут восстановлены после перезагрузки Linux.' : 'Предыдущие правила восстановлены.'); }
    catch (err) { message(err.message); }
    finally { changeBusy = false; await pollChanges(); }
  });
}
setInterval(() => {
  if (!changeBusy) pollChanges();
  if (isAdmin() && !$('app').hidden && location.hash === '#audit') void refreshSIEM();
}, 3000);
setInterval(updateCountdown, 1000);
