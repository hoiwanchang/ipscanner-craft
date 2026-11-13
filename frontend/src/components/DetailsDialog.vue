<script setup lang="ts">
import { compressPorts } from '../api';
import type { HostResult } from '../types';

defineProps<{ row: HostResult; ports: number[] }>();

const emit = defineEmits<{ close: []; rescan: [] }>();

function openText(row: HostResult) {
  if (row.openPorts.length === 0) return 'none found';
  return compressPorts(row.openPorts, 40) || row.openPorts.join(', ');
}

function ping(row: HostResult) {
  if (row.pingMs === null) return row.alive ? 'under 1 ms' : 'no answer';
  return `${row.pingMs.toFixed(1)} ms`;
}
</script>

<template>
  <div class="overlay" @mousedown.self="emit('close')">
    <div class="dialog">
      <h2>{{ row.ip }}</h2>
      <div class="body">
        <div class="detail-grid">
          <span class="k">Status</span>
          <span>
            <span class="status">
              <span
                class="dot"
                :class="!row.alive ? 'down' : row.openPorts.length ? 'open' : 'up'"
              ></span>
              {{ row.alive ? 'Alive' : 'Dead' }}
            </span>
          </span>
          <span class="k">Host name</span><span>{{ row.hostname || 'not resolved' }}</span>
          <span class="k">Response time</span><span>{{ ping(row) }}</span>
          <span class="k">Answered to</span><span>{{ row.method || 'nothing' }}</span>
          <span class="k">Open ports</span>
          <span class="mono">{{ openText(row) }}</span>
          <span class="k">Ports checked</span>
          <span class="mono">{{ row.portsScanned ? `${ports.length}: ${compressPorts(ports, 24)}` : 'not checked' }}</span>
        </div>
      </div>
      <div class="footer">
        <button @click="emit('rescan')">Rescan</button>
        <button class="primary" @click="emit('close')">Close</button>
      </div>
    </div>
  </div>
</template>