<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { compressPorts, SUMMARY_COLUMN_THRESHOLD } from '../api';
import type { HostResult, SortKey } from '../types';

const props = defineProps<{
  rows: HostResult[];
  ports: number[];
  sortKey: SortKey;
  sortDir: 'asc' | 'desc';
  selectedIp: string | null;
  scanning: boolean;
}>();

const emit = defineEmits<{
  sort: [key: SortKey];
  select: [row: HostResult];
  context: [payload: { row: HostResult; x: number; y: number }];
  details: [row: HostResult];
}>();

const viewport = ref<HTMLElement | null>(null);
const scrollTop = ref(0);
const viewHeight = ref(600);
const narrow = ref(false);

let media: MediaQueryList | null = null;
let observer: ResizeObserver | null = null;

const rowHeight = computed(() => (narrow.value ? 30 : 24));

const summaryOnly = computed(() => props.ports.length > SUMMARY_COLUMN_THRESHOLD);

const columns = computed(() => {
  if (narrow.value) return ['110px', 'minmax(48px, 1fr)', 'minmax(88px, 1.1fr)', '52px', '56px'].join(' ');
  const portCols = summaryOnly.value ? [] : props.ports.map(() => '68px');
  const portsWidth = summaryOnly.value ? 'minmax(180px, 1.6fr)' : '104px';
  return ['140px', 'minmax(150px, 1fr)', portsWidth, '92px', '78px', ...portCols].join(' ');
});

const first = computed(() =>
  Math.max(0, Math.floor(scrollTop.value / rowHeight.value) - 6),
);
const last = computed(() =>
  Math.min(
    props.rows.length,
    Math.ceil((scrollTop.value + viewHeight.value) / rowHeight.value) + 6,
  ),
);
const visible = computed(() =>
  props.rows.slice(first.value, last.value).map((row, i) => ({ row, index: first.value + i })),
);

function onScroll() {
  if (viewport.value) scrollTop.value = viewport.value.scrollTop;
}

function syncMedia() {
  narrow.value = media?.matches ?? false;
}

onMounted(() => {
  media = window.matchMedia('(max-width: 760px)');
  syncMedia();
  media.addEventListener('change', syncMedia);
  if (viewport.value) {
    viewHeight.value = viewport.value.clientHeight;
    observer = new ResizeObserver(() => {
      if (viewport.value) viewHeight.value = viewport.value.clientHeight;
    });
    observer.observe(viewport.value);
  }
});

onBeforeUnmount(() => {
  media?.removeEventListener('change', syncMedia);
  observer?.disconnect();
});

watch(
  () => props.rows.length,
  (length) => {
    if (length === 0 && viewport.value) {
      viewport.value.scrollTop = 0;
      scrollTop.value = 0;
    }
  },
);

function mark(key: SortKey) {
  if (props.sortKey !== key) return '';
  return props.sortDir === 'asc' ? '▲' : '▼';
}

function statusLabel(row: HostResult) {
  return row.alive ? 'Alive' : 'Dead';
}

function dotClass(row: HostResult) {
  if (!row.alive) return 'down';
  return row.openPorts.length > 0 ? 'open' : 'up';
}

function portState(row: HostResult, port: number) {
  if (!row.portsScanned) return '–';
  return row.openPorts.includes(port) ? 'open' : 'closed';
}

function portSummary(row: HostResult) {
  if (!row.portsScanned) return '–';
  if (row.openPorts.length === 0) return '–';
  const text = compressPorts(row.openPorts);
  return `${row.openPorts.length}: ${text}`;
}

function pingText(row: HostResult) {
  if (row.pingMs === null) return row.alive ? '<1 ms' : '–';
  return `${row.pingMs < 10 ? row.pingMs.toFixed(1) : Math.round(row.pingMs)} ms`;
}

function onContext(row: HostResult, event: MouseEvent) {
  event.preventDefault();
  emit('select', row);
  emit('context', { row, x: event.clientX, y: event.clientY });
}

function onKey(event: KeyboardEvent) {
  if (props.rows.length === 0) return;
  const current = props.rows.findIndex((r) => r.ip === props.selectedIp);
  let next = current;
  if (event.key === 'ArrowDown') next = current < 0 ? 0 : Math.min(props.rows.length - 1, current + 1);
  else if (event.key === 'ArrowUp') next = current < 0 ? 0 : Math.max(0, current - 1);
  else if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = props.rows.length - 1;
  else if (event.key === 'Enter' && current >= 0) {
    emit('details', props.rows[current]);
    return;
  } else return;
  event.preventDefault();
  emit('select', props.rows[next]);
  const el = viewport.value;
  if (!el) return;
  const top = next * rowHeight.value;
  if (top < el.scrollTop) el.scrollTop = top;
  else if (top + rowHeight.value > el.scrollTop + el.clientHeight)
    el.scrollTop = top + rowHeight.value - el.clientHeight;
}
</script>

<template>
  <div class="results" ref="viewport" tabindex="0" @scroll="onScroll" @keydown="onKey">
    <div class="grid-header" :style="{ gridTemplateColumns: columns }">
      <div class="cell" @click="emit('sort', 'ip')">
        IP <span class="sort-mark">{{ mark('ip') }}</span>
      </div>
      <div class="cell" @click="emit('sort', 'hostname')">
        Hostname <span class="sort-mark">{{ mark('hostname') }}</span>
      </div>
      <div class="cell" @click="emit('sort', 'ports')">
        {{ summaryOnly ? `Opening Ports (${ports.length} checked)` : 'Ports' }}
        <span class="sort-mark">{{ mark('ports') }}</span>
      </div>
      <div class="cell" @click="emit('sort', 'status')">
        Status <span class="sort-mark">{{ mark('status') }}</span>
      </div>
      <div class="cell right" @click="emit('sort', 'ping')">
        Ping <span class="sort-mark">{{ mark('ping') }}</span>
      </div>
      <div
        v-for="port in summaryOnly ? [] : ports"
        :key="port"
        class="cell center col-port"
        @click="emit('sort', `port:${port}`)"
      >
        {{ port }} <span class="sort-mark">{{ mark(`port:${port}`) }}</span>
      </div>
    </div>

    <div v-if="rows.length === 0" class="empty-state">
      <div v-if="scanning">Scanning… results appear here as hosts answer.</div>
      <div v-else>
        No results yet.<br />
        Enter an IP range or a CIDR block above, then press Start.
      </div>
    </div>

    <div v-else class="rows" :style="{ height: rows.length * rowHeight + 'px' }">
      <div
        v-for="item in visible"
        :key="item.row.ip"
        class="row"
        :class="{ alt: item.index % 2 === 1, selected: item.row.ip === selectedIp }"
        :style="{ top: item.index * rowHeight + 'px', gridTemplateColumns: columns }"
        @click="emit('select', item.row)"
        @dblclick="emit('details', item.row)"
        @contextmenu="onContext(item.row, $event)"
      >
        <div class="cell mono">{{ item.row.ip }}</div>
        <div class="cell">{{ item.row.hostname || '–' }}</div>
        <div
          class="cell mono ports-summary"
          :title="summaryOnly ? item.row.openPorts.join(', ') : ''"
        >{{ summaryOnly ? portSummary(item.row) : item.row.openPorts.join(', ') || '–' }}</div>
        <div class="cell">
          <span class="status">
            <span class="dot" :class="dotClass(item.row)"></span>{{ statusLabel(item.row) }}
          </span>
        </div>
        <div class="cell right mono">{{ pingText(item.row) }}</div>
        <div
          v-for="port in summaryOnly ? [] : ports"
          :key="port"
          class="cell center col-port"
          :class="portState(item.row, port) === 'open' ? 'port-open' : 'port-closed'"
        >
          {{ portState(item.row, port) }}
        </div>
      </div>
    </div>
  </div>
</template>