<script setup lang="ts">
import { ref } from 'vue';
import { save } from '@tauri-apps/plugin-dialog';

const props = defineProps<{ suggestedPath: string; count: number; shown: number }>();

const emit = defineEmits<{
  close: [];
  submit: [value: { path: string; format: 'csv' | 'json'; scope: 'shown' | 'all' }];
}>();

const path = ref(props.suggestedPath);
const format = ref<'csv' | 'json'>('csv');
const scope = ref<'shown' | 'all'>('shown');
const problem = ref('');

async function browse() {
  try {
    const chosen = await save({
      defaultPath: path.value,
      filters: [
        { name: 'CSV table', extensions: ['csv'] },
        { name: 'JSON document', extensions: ['json'] },
      ],
    });
    if (chosen) {
      path.value = chosen;
      format.value = chosen.toLowerCase().endsWith('.json') ? 'json' : 'csv';
    }
  } catch {
    problem.value = 'The system save window is unavailable here; type a path instead.';
  }
}

function submit() {
  const trimmed = path.value.trim();
  if (!trimmed) {
    problem.value = 'Choose where to save the file.';
    return;
  }
  const wanted = trimmed.toLowerCase().endsWith('.json') ? 'json' : format.value;
  emit('submit', { path: trimmed, format: wanted, scope: scope.value });
}
</script>

<template>
  <div class="overlay" @mousedown.self="emit('close')">
    <div class="dialog">
      <h2>Export results</h2>
      <div class="body">
        <div class="form-row">
          <label>Save to</label>
          <input v-model="path" type="text" spellcheck="false" />
          <button @click="browse">Browse…</button>
        </div>
        <div class="form-row">
          <label>Format</label>
          <select v-model="format">
            <option value="csv">CSV (spreadsheet)</option>
            <option value="json">JSON</option>
          </select>
        </div>
        <div class="form-row">
          <label>Rows</label>
          <select v-model="scope">
            <option value="shown">Only the {{ shown }} shown</option>
            <option value="all">All {{ count }} scanned</option>
          </select>
        </div>
        <p class="note">
          The current sorting and the open-port columns are kept in the file.
          <template v-if="problem"><br />{{ problem }}</template>
        </p>
      </div>
      <div class="footer">
        <button @click="emit('close')">Cancel</button>
        <button class="primary" @click="submit">Export</button>
      </div>
    </div>
  </div>
</template>