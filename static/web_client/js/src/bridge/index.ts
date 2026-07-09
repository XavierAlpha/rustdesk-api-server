import { isMobileDevice } from '../core/platform';
import { WebRuntime } from '../runtime/runtime';

export function attachBridge(runtime: WebRuntime): void {
  window.isMobile = isMobileDevice;
  window.setByName = runtime.setByName.bind(runtime);
  window.getByName = runtime.getByName.bind(runtime);
  window.__CAMELLIA_WEB_BRIDGE__ = { runtime };
  window.init = runtime.init.bind(runtime);
}
