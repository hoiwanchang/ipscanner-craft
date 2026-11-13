<script setup lang="ts">
import type { DisplayFilter, PingMethod, RangeMode } from '../types';

defineProps<{
  mode: RangeMode;
  start: string;
  end: string;
  cidr: string;
  threads: number;
  timeoutMs: number;
  pingMethod: PingMethod;
  portsText: string;
  filter: DisplayFilter;
  theme: 'light' | 'dark';
  scanning: boolean;
  icmpAvailable: boolean;
  mobile: boolean;
  hint: string;
  hintBad: boolean;
}>();

const emit = defineEmits<{
  'update:mode': [value: RangeMode];
  'update:start': [value: string];
  'update:end': [value: string];
  'update:cidr': [value: string];
  'update:threads': [value: number];
  'update:timeoutMs': [value: number];
  'update:pingMethod': [value: PingMethod];
  'update:portsText': [value: string];
  'update:filter': [value: DisplayFilter];
  toggleTheme: [];
  start: [];
  stop: [];
  preferences: [];
  export: [];
}>();

function num(event: Event) {
  return Number((event.target as HTMLInputElement).value);
}
function text(event: Event) {
  return (event.target as HTMLInputElement | HTMLSelectElement).value;
}
</script>

<template>
  <header class="toolbar">
    <div class="toolbar-row">
      <select
        :value="mode"
        title="Choose how to describe the addresses to scan"
        @change="emit('update:mode', text($event) as RangeMode)"
      >
        <option value="range">IP Range</option>
        <option value="cidr">CIDR</option>
      </select>

      <template v-if="mode === 'range'">
        <input
          class="ip mono"
          :value="start"
          spellcheck="false"
          title="First address"
          @input="emit('update:start', text($event))"
          @keyup.enter="emit('start')"
        />
        <label class="caption">to</label>
        <input
          class="ip mono"
          :value="end"
          spellcheck="false"
          title="Last address, or just its last number"
          @input="emit('update:end', text($event))"
          @keyup.enter="emit('start')"
        />
      </template>
      <input
        v-else
        class="cidr mono"
        :value="cidr"
        spellcheck="false"
        title="For example 192.168.1.0/24"
        @input="emit('update:cidr', text($event))"
        @keyup.enter="emit('start')"
      />

      <button v-if="!scanning" class="primary" @click="emit('start')">Start</button>
      <button v-else class="primary stop" @click="emit('stop')">Stop</button>
      <button class="icon" title="Preferences" @click="emit('preferences')">⚙</button>

      <span class="spacer"></span>
      <span class="count-hint" :class="{ bad: hintBad }">{{ hint }}</span>
    </div>

    <div class="toolbar-row secondary">
      <label class="caption">Ping</label>
      <select
        class="ping"
        :value="pingMethod"
        title="How to decide whether a host is up"
        @change="emit('update:pingMethod', text($event) as PingMethod)"
      >
        <option value="icmp-tcp">ICMP + TCP</option>
        <option value="icmp" :disabled="!icmpAvailable">ICMP only</option>
        <option value="tcp">TCP only</option>
      </select>

      <label class="caption">Threads</label>
      <input
        class="num"
        type="number"
        min="1"
        max="512"
        :value="threads"
        title="How many addresses to probe at once"
        @input="emit('update:threads', num($event))"
      />

      <label class="caption">Timeout</label>
      <input
        class="num"
        type="number"
        min="50"
        max="30000"
        step="100"
        :value="timeoutMs"
        title="How long to wait for each answer, in milliseconds"
        @input="emit('update:timeoutMs', num($event))"
      />
      <label class="caption">ms</label>

      <label class="caption">Ports</label>
      <input
        class="ports mono"
        :value="portsText"
        spellcheck="false"
        title="Comma separated port numbers; each one gets a column"
        @input="emit('update:portsText', text($event))"
      />

      <span class="spacer"></span>

      <label class="caption">Show</label>
      <select
        class="filter"
        :value="filter"
        title="Which results to show in the table"
        @change="emit('update:filter', text($event) as DisplayFilter)"
      >
        <option value="all">All hosts</option>
        <option value="alive">Alive only</option>
        <option value="dead">Dead only</option>
        <option value="open">With open ports</option>
      </select>
      <button title="Save the results as CSV or JSON" @click="emit('export')">Export…</button>
      <button
        :title="theme === 'dark' ? 'Switch to the light theme' : 'Switch to the dark theme'"
        @click="emit('toggleTheme')"
      >
        {{ theme === 'dark' ? 'Light' : 'Dark' }}
      </button>
      <span v-if="mobile" class="count-hint">TCP probing</span>
    </div>
  </header>
</template>