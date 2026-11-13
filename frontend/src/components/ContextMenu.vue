<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue';
import type { HostResult } from '../types';

const props = defineProps<{ row: HostResult; x: number; y: number }>();

const emit = defineEmits<{
  close: [];
  action: [name: string];
}>();

const menu = ref<HTMLElement | null>(null);
const left = ref(props.x);
const top = ref(props.y);

function place() {
  const el = menu.value;
  if (!el) return;
  left.value = Math.min(props.x, window.innerWidth - el.offsetWidth - 6);
  top.value = Math.min(props.y, window.innerHeight - el.offsetHeight - 6);
}

function away(event: MouseEvent) {
  if (menu.value && !menu.value.contains(event.target as Node)) emit('close');
}

function onKey(event: KeyboardEvent) {
  if (event.key === 'Escape') emit('close');
}

function close() {
  emit('close');
}

onMounted(() => {
  place();
  window.addEventListener('mousedown', away);
  window.addEventListener('keydown', onKey);
  window.addEventListener('resize', close);
});

onBeforeUnmount(() => {
  window.removeEventListener('mousedown', away);
  window.removeEventListener('keydown', onKey);
  window.removeEventListener('resize', close);
});

function run(name: string, enabled = true) {
  if (!enabled) return;
  emit('action', name);
  emit('close');
}
</script>

<template>
  <div class="ctxmenu" ref="menu" :style="{ left: left + 'px', top: top + 'px' }">
    <div class="ctxitem" @click="run('copy-ip')">Copy IP<span class="ctxhint">{{ row.ip }}</span></div>
    <div class="ctxitem" :class="{ disabled: !row.hostname }" @click="run('copy-host', !!row.hostname)">
      Copy hostname
    </div>
    <div class="ctxitem" @click="run('copy-row')">Copy row</div>
    <div class="ctxsep"></div>
    <div class="ctxitem" @click="run('open-http')">Open in browser<span class="ctxhint">http</span></div>
    <div class="ctxitem" @click="run('open-https')">Open in browser<span class="ctxhint">https</span></div>
    <div class="ctxsep"></div>
    <div class="ctxitem" @click="run('rescan')">Rescan this host</div>
    <div class="ctxitem" @click="run('details')">Details…</div>
  </div>
</template>