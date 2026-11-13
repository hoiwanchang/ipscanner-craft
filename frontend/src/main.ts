import { createApp } from 'vue';
import App from './App.vue';
import './styles.css';
import { captureWhenAsked } from './screenshot';

createApp(App).mount('#app');
void captureWhenAsked();