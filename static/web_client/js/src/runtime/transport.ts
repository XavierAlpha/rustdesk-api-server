import { Logger } from '../core/logger';
import { SecretBoxCipher } from './crypto';

export type TransportState = 'idle' | 'connecting' | 'open' | 'closed' | 'error';

type MessageHandler = (data: Uint8Array) => void;
type CloseHandler = (event: CloseEvent) => void;

export class WebSocketTransport {
  private socket?: WebSocket;
  private state: TransportState = 'idle';
  private readonly logger: Logger;
  private readonly handlers: MessageHandler[] = [];
  private readonly closeHandlers: CloseHandler[] = [];
  private cipher?: SecretBoxCipher;
  private lastSendDropLogTs = 0;

  constructor(scope = 'transport') {
    this.logger = new Logger(scope);
  }

  getState(): TransportState {
    return this.state;
  }

  onMessage(handler: MessageHandler): () => void {
    this.handlers.push(handler);
    return () => {
      const index = this.handlers.indexOf(handler);
      if (index >= 0) {
        this.handlers.splice(index, 1);
      }
    };
  }

  onClose(handler: CloseHandler): () => void {
    this.closeHandlers.push(handler);
    return () => {
      const index = this.closeHandlers.indexOf(handler);
      if (index >= 0) {
        this.closeHandlers.splice(index, 1);
      }
    };
  }

  setCipher(cipher?: SecretBoxCipher): void {
    this.cipher = cipher;
  }

  async connect(url: string, timeoutMs = 10000): Promise<void> {
    if (
      this.socket &&
      this.state === 'open' &&
      this.socket.readyState === WebSocket.OPEN
    ) {
      return;
    }
    const previous = this.socket;
    this.socket = undefined;
    if (previous && previous.readyState < WebSocket.CLOSING) {
      try {
        previous.close();
      } catch {
        // noop
      }
    }
    this.state = 'connecting';
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer: number | undefined;
      const finish = (ok: boolean, err?: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer !== undefined) {
          window.clearTimeout(timer);
          timer = undefined;
        }
        if (ok) {
          resolve();
        } else {
          reject(err);
        }
      };
      try {
        const socket = new WebSocket(url);
        this.socket = socket;
        socket.binaryType = 'arraybuffer';
        socket.onopen = () => {
          if (this.socket !== socket) {
            try {
              socket.close();
            } catch {
              // noop
            }
            finish(false, new Error('WebSocket connection superseded'));
            return;
          }
          this.state = 'open';
          this.logger.info(`WebSocket connected: ${url}`);
          finish(true);
        };
        socket.onerror = (event) => {
          if (this.socket === socket) {
            this.state = 'error';
          }
          this.logger.error(`WebSocket error: ${url}`);
          finish(false, event);
        };
        socket.onclose = (event) => {
          if (this.socket !== socket) {
            return;
          }
          this.state = 'closed';
          this.socket = undefined;
          this.logger.warn(`WebSocket closed: ${url}`);
          for (const handler of this.closeHandlers) {
            handler(event);
          }
          if (!settled) {
            finish(
              false,
              new Error(
                `WebSocket closed before ready (code=${event.code}, reason=${event.reason || 'n/a'})`
              )
            );
          }
        };
        socket.onmessage = (event) => {
          if (event.data instanceof ArrayBuffer) {
            let payload = new Uint8Array(event.data) as Uint8Array;
            if (this.cipher) {
              try {
                payload = this.cipher.decrypt(payload) as Uint8Array;
              } catch (err) {
                this.logger.error('Failed to decrypt WebSocket payload', err);
                return;
              }
            }
            for (const handler of this.handlers) {
              handler(payload);
            }
          }
        };
        if (timeoutMs > 0) {
          timer = window.setTimeout(() => {
            if (settled) {
              return;
            }
            if (this.socket === socket) {
              this.state = 'error';
              this.socket = undefined;
            }
            this.logger.warn(`WebSocket connect timeout: ${url}`);
            try {
              socket.close();
            } catch {
              // noop
            }
            finish(false, new Error(`WebSocket connect timeout: ${timeoutMs}ms`));
          }, timeoutMs);
        }
      } catch (err) {
        this.state = 'error';
        finish(false, err);
      }
    });
  }

  send(data: Uint8Array): boolean {
    const socket = this.socket;
    if (
      !socket ||
      this.state !== 'open' ||
      socket.readyState !== WebSocket.OPEN
    ) {
      const now = Date.now();
      if (now - this.lastSendDropLogTs >= 5000) {
        const readyState = socket ? socket.readyState : -1;
        this.logger.warn(
          `send() dropped because socket not open (state=${this.state}, readyState=${readyState})`
        );
        this.lastSendDropLogTs = now;
      }
      return false;
    }
    try {
      const payload = this.cipher ? this.cipher.encrypt(data) : data;
      // TypeScript 6 narrows WebSocket.send() to ArrayBuffer-backed views.
      // Copy to a fresh Uint8Array so the backing buffer is always ArrayBuffer.
      socket.send(payload.slice());
      return true;
    } catch (err) {
      this.state = 'error';
      this.logger.warn('send() failed', err);
      return false;
    }
  }

  close(): void {
    const socket = this.socket;
    this.socket = undefined;
    if (socket && socket.readyState < WebSocket.CLOSING) {
      socket.close();
    }
    this.state = 'closed';
  }
}
