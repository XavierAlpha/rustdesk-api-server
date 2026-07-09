import { WebRuntime } from './runtime/runtime';
import { attachBridge } from './bridge';

const runtime = new WebRuntime();
attachBridge(runtime);

// Allow direct init in case the host calls it late.
if (document.readyState === 'complete') {
  runtime.init();
} else {
  window.addEventListener('load', () => runtime.init());
}
