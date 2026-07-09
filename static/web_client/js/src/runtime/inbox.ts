import { WebSocketTransport } from './transport';

export class MessageInbox {
  private readonly queue: Uint8Array[] = [];
  private readonly waiters: Array<(data: Uint8Array) => void> = [];
  private readonly unsubscribe: () => void;

  constructor(transport: WebSocketTransport) {
    this.unsubscribe = transport.onMessage((data) => this.push(data));
  }

  next(timeoutMs = 15000): Promise<Uint8Array> {
    if (this.queue.length > 0) {
      return Promise.resolve(this.queue.shift() as Uint8Array);
    }
    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => {
        const idx = this.waiters.indexOf(resolve);
        if (idx >= 0) {
          this.waiters.splice(idx, 1);
        }
        reject(new Error('timeout waiting for message'));
      }, timeoutMs);
      this.waiters.push((data) => {
        window.clearTimeout(timer);
        resolve(data);
      });
    });
  }

  close(): void {
    this.unsubscribe();
    this.queue.length = 0;
    this.waiters.length = 0;
  }

  pushFront(data: Uint8Array): void {
    this.queue.unshift(data);
  }

  private push(data: Uint8Array): void {
    if (this.waiters.length > 0) {
      const waiter = this.waiters.shift();
      if (waiter) {
        waiter(data);
      }
      return;
    }
    this.queue.push(data);
  }
}
