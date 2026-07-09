export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};
const ACTIVE_LEVEL: LogLevel = import.meta.env.PROD ? 'error' : 'info';

function shouldLog(level: LogLevel): boolean {
  return LEVEL_RANK[level] >= LEVEL_RANK[ACTIVE_LEVEL];
}

export class Logger {
  private readonly scope: string;
  private readonly debugEnabled: boolean;

  constructor(scope: string, debugEnabled = false) {
    this.scope = scope;
    this.debugEnabled = debugEnabled;
  }

  debug(message: string, ...args: unknown[]): void {
    if (!this.debugEnabled || !shouldLog('debug')) {
      return;
    }
    console.debug(`[${this.scope}] ${message}`, ...args);
  }

  info(message: string, ...args: unknown[]): void {
    if (!shouldLog('info')) {
      return;
    }
    console.info(`[${this.scope}] ${message}`, ...args);
  }

  warn(message: string, ...args: unknown[]): void {
    if (!shouldLog('warn')) {
      return;
    }
    console.warn(`[${this.scope}] ${message}`, ...args);
  }

  error(message: string, ...args: unknown[]): void {
    if (!shouldLog('error')) {
      return;
    }
    console.error(`[${this.scope}] ${message}`, ...args);
  }
}
