<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
  state: string;
  scanned: number;
  total: number;
  alive: number;
  dead: number;
  shown: number;
  scanning: boolean;
}>();

const percent = computed(() =>
  props.total > 0 ? Math.min(100, (props.scanned / props.total) * 100) : 0,
);
</script>

<template>
  <footer class="statusbar">
    <span class="state">{{ state }}</span>
    <div class="progress" :title="`${Math.round(percent)}% complete`">
      <div class="progress-fill" :style="{ width: percent + '%' }"></div>
    </div>
    <span class="tally">Alive: <b>{{ alive }}</b></span>
    <span class="tally">Dead: <b>{{ dead }}</b></span>
    <span class="tally shown">Shown: <b>{{ shown }}</b></span>
    <span class="tally">Scanned: <b>{{ scanned }}</b> / {{ total }}</span>
  </footer>
</template>