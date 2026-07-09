export type RuntimeEvent = {
  name: string;
  [key: string]: unknown;
};

type EventSink = (payload: string) => void;

export class EventDispatcher {
  private globalSink?: EventSink;
  private registeredSink?: EventSink;
  private readonly listeners: Array<(event: RuntimeEvent) => void> = [];

  bindGlobalSink(fn?: EventSink): void {
    this.globalSink = fn;
  }

  bindRegisteredSink(fn?: EventSink): void {
    this.registeredSink = fn;
  }

  onEmit(fn: (event: RuntimeEvent) => void): void {
    this.listeners.push(fn);
  }

  emit(event: RuntimeEvent): void {
    const payload = JSON.stringify(event);
    for (const listener of this.listeners) {
      listener(event);
    }
    if (this.registeredSink) {
      this.registeredSink(payload);
    }
    if (this.globalSink) {
      this.globalSink(payload);
    }
  }
}
