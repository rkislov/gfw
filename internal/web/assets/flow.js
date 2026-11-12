'use strict';

const flowForm = $('flow-form');
let flowLoading = false, flowSession = 0;
const flowNumber = new Intl.NumberFormat('ru-RU');

function renderFlowDraft() {
  const config = snapshot.config;
  const enabled = Boolean(config.flowtable);
  const selected = config.flowtable?.interfaces || [];
  flowForm.elements.enabled.checked = enabled;
  $('flow-ports').disabled = !enabled;
  const ports = [...new Set(config.zones.filter(zone => !['vpn', 'management'].includes(zone.kind)).flatMap(zone => zone.interfaces))].sort();
  $('flow-interfaces').replaceChildren(...ports.map(name => {
    const label = node('label', '', 'flex items-center gap-2 rounded-lg border px-3 py-2 text-sm');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.name = 'interface';
    box.value = name;
    box.checked = selected.includes(name);
    box.className = 'mt-0 size-4 w-4 p-0 accent-teal-700';
    label.append(box, node('span', name));
    return label;
  }));
  if (!ports.length) $('flow-interfaces').append(node('p', 'Добавьте интерфейсы в транзитные зоны.', 'text-sm text-slate-500'));
  const rules = config.rules.filter(rule => rule.enabled && rule.fast_path).length;
  $('flow-draft').textContent = enabled ? `В черновике ${selected.length} интерфейсов и ${rules} правил с ускорением.` : 'Ускорение в черновике выключено.';
}

flowForm.elements.enabled.addEventListener('change', () => { $('flow-ports').disabled = !flowForm.elements.enabled.checked; });
flowForm.addEventListener('submit', event => {
  event.preventDefault();
  if (!snapshot) return;
  const enabled = flowForm.elements.enabled.checked;
  const interfaces = new FormData(flowForm).getAll('interface');
  if (enabled && (interfaces.length < 2 || interfaces.length > 16)) {
    $('flow-draft').textContent = 'Выберите от 2 до 16 интерфейсов.';
    return;
  }
  snapshot.config.flowtable = enabled ? {interfaces} : undefined;
  markDirty();
  renderFlowDraft();
});

async function refreshFlow() {
  if (flowLoading || $('app').hidden) return;
  const session = flowSession;
  flowLoading = true;
  try {
    const state = await api('/firewall/flow');
    if (session !== flowSession) return;
    $('flow-status').textContent = state.active ? `Ускорение работает · ревизия ${state.revision} · ${state.interfaces.join(', ')}` :
      state.configured ? 'Ускорение приостановлено' : state.available ? 'Ускорение выключено' : 'Нужен Linux-агент';
    $('flow-reason').textContent = state.reason || '';
    $('flow-excluded').replaceChildren(...state.excluded.map(port => node('li', `${port.interface} · ${port.reason}`)));
    $('flow-counters').hidden = !state.active || !state.counters;
    if (state.counters) {
      for (const [id, value] of Object.entries({tcp: state.counters.tcp, udp: state.counters.udp, packets: state.counters.ingress_packets, bytes: state.counters.ingress_bytes})) {
        $('flow-' + id).textContent = flowNumber.format(value);
      }
    }
  } catch (err) {
    if (session === flowSession) {
      $('flow-counters').hidden = true;
      $('flow-reason').textContent = err.message;
    }
  } finally {
    if (session === flowSession) flowLoading = false;
  }
}

function resetFlow() {
  flowSession++;
  flowLoading = false;
  flowForm.reset();
  $('flow-counters').hidden = true;
  for (const id of ['flow-interfaces', 'flow-status', 'flow-reason', 'flow-excluded', 'flow-draft']) $(id).replaceChildren();
}

setInterval(() => {
  if (!$('page-firewall').hidden && !$('app').hidden) void refreshFlow();
}, 3000);
