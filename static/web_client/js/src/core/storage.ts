export class StorageStore {
  private readonly prefix: string;
  private readonly memory = new Map<string, string>();

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  get(key: string, fallback = ''): string {
    if (this.memory.has(key)) {
      return this.memory.get(key) as string;
    }
    try {
      const raw = window.localStorage.getItem(this.prefix + key);
      if (raw !== null) {
        return raw;
      }
    } catch {
      // Ignore storage errors.
    }
    return fallback;
  }

  set(key: string, value: unknown, persist = true): void {
    const raw = value === undefined || value === null ? '' : String(value);
    this.memory.set(key, raw);
    if (!persist) {
      return;
    }
    try {
      window.localStorage.setItem(this.prefix + key, raw);
    } catch {
      // Ignore storage errors.
    }
  }

  remove(key: string, persist = true): void {
    this.memory.delete(key);
    if (!persist) {
      return;
    }
    try {
      window.localStorage.removeItem(this.prefix + key);
    } catch {
      // Ignore storage errors.
    }
  }

  ensure(key: string, valueFactory: () => string): string {
    const existing = this.get(key);
    if (existing) {
      return existing;
    }
    const next = valueFactory();
    this.set(key, next);
    return next;
  }

  getJson<T>(key: string, fallback: T): T {
    const raw = this.get(key, '');
    if (!raw) {
      return fallback;
    }
    try {
      return JSON.parse(raw) as T;
    } catch {
      return fallback;
    }
  }

  setJson(key: string, value: unknown): void {
    this.set(key, JSON.stringify(value));
  }
}
