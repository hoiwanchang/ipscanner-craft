<script setup lang="ts">
import { ref, watch } from 'vue';
import type { PingMethod } from '../types';

const props = defineProps<{
  threads: number;
  timeoutMs: number;
  pingMethod: PingMethod;
  portsText: string;
  resolveHostnames: boolean;
  scanPorts: boolean;
  portsAliveOnly: boolean;
  icmpAvailable: boolean;
  masscanAvailable: boolean;
  masscanDriver: boolean;
  mobile: boolean;
}>();

const emit = defineEmits<{
  close: [];
  apply: [
    value: {
      threads: number;
      timeoutMs: number;
      pingMethod: PingMethod;
      portsText: string;
      resolveHostnames: boolean;
      scanPorts: boolean;
      portsAliveOnly: boolean;
    },
  ];
}>();

const draft = ref({ ...props });

watch(
  () => props.threads,
  () => {
    draft.value = { ...props };
  },
);

function save() {
  const icmpOnly = draft.value.pingMethod === 'icmp';
  emit('apply', {
    threads: Math.min(100, Math.max(1, Math.round(draft.value.threads || 1))),
    timeoutMs: Math.min(30000, Math.max(50, Math.round(draft.value.timeoutMs || 500))),
    pingMethod: draft.value.pingMethod,
    portsText: draft.value.portsText,
    resolveHostnames: draft.value.resolveHostnames,
    scanPorts: icmpOnly ? false : draft.value.scanPorts,
    portsAliveOnly: draft.value.portsAliveOnly,
  });
  emit('close');
}
</script>

<template>
  <div class="overlay" @mousedown.self="emit('close')">
    <div class="dialog">
      <h2>Preferences</h2>
      <div class="body">
        <div class="form-row">
          <label>Ping method</label>
          <select v-model="draft.pingMethod">
            <option value="icmp-tcp">ICMP, then TCP if silent</option>
            <option value="icmp" :disabled="!icmpAvailable">ICMP only</option>
            <option value="tcp">TCP only</option>
            <option value="masscan" :disabled="!masscanAvailable || !masscanDriver">
              masscan (fastest, needs admin)
            </option>
          </select>
        </div>
        <div class="form-row">
          <label>Threads</label>
          <input v-model.number="draft.threads" type="number" min="1" max="100" />
        </div>
        <div class="form-row">
          <label>Timeout (ms)</label>
          <input v-model.number="draft.timeoutMs" type="number" min="50" max="30000" step="100" />
        </div>
        <div class="form-row">
          <label>Ports</label>
          <input v-model="draft.portsText" type="text" spellcheck="false" :disabled="draft.pingMethod === 'icmp'" />
        </div>
        <div class="check-row">
          <input id="pref-resolve" v-model="draft.resolveHostnames" type="checkbox" />
          <label for="pref-resolve">Look up host names</label>
        </div>
        <div class="check-row">
          <input
            id="pref-ports"
            v-model="draft.scanPorts"
            type="checkbox"
            :disabled="draft.pingMethod === 'icmp'"
          />
          <label for="pref-ports">Check the ports above</label>
        </div>
        <div class="check-row">
          <input
            id="pref-alive"
            v-model="draft.portsAliveOnly"
            type="checkbox"
            :disabled="!draft.scanPorts"
          />
          <label for="pref-alive">Only check ports on hosts that answered</label>
        </div>
        <p class="note">
          Separate ports with any symbol you like — commas, Chinese commas ，、 spaces,
          slashes… (ports are digits only). Ranges use - or ~ e.g. 8000-8100 (up to 1024).
          Each port gets its own column while there are 8 or fewer; wider checks collapse
          into one Opening Ports column with compressed ranges.
          <template v-if="draft.pingMethod === 'icmp'">
            <br />ICMP only: no TCP sockets are opened, port checking is off.
          </template>
          <template v-if="draft.pingMethod === 'masscan'">
            <br />masscan: raw-socket SYN blast via Npcap — only live hosts appear in the
            table. Run the app as administrator for it to bind the adapter.
          </template>
          <template v-if="!masscanDriver">
            <br />masscan needs the Npcap driver (npcap.com → install with WinPcap-compatible
            mode); it is not installed here.
          </template>
          <template v-if="!icmpAvailable">
            <br />ICMP is not available here, so hosts are probed over TCP.
          </template>
          <template v-if="mobile">
            <br />On phones only TCP probing is used.
          </template>
        </p>
      </div>
      <div class="footer">
        <button @click="emit('close')">Cancel</button>
        <button class="primary" @click="save">Save</button>
      </div>
    </div>
  </div>
</template>