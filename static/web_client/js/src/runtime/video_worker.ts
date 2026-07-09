type CodecType = 'vp9' | 'av1' | 'h264' | 'h265';

type AttachSurfaceMessage = {
  type: 'attach_surface';
  canvas: OffscreenCanvas;
  width: number;
  height: number;
};

type ResizeSurfaceMessage = {
  type: 'resize_surface';
  width: number;
  height: number;
};

type SetPolicyMessage = {
  type: 'set_policy';
  renderQuality: 'low' | 'balanced' | 'best' | 'custom';
  customQuality?: number;
  customFps?: number;
};
type SetActiveDisplayMessage = {
  type: 'set_active_display';
  display: number;
  reset?: boolean;
};
type DecodeMessage = {
  type: 'decode';
  codec: CodecType;
  display: number;
  data: Uint8Array;
  key: boolean;
  pts: number;
};

type DetachSurfaceMessage = { type: 'detach_surface' };
type CloseMessage = { type: 'close' };

type WorkerRequest =
  | AttachSurfaceMessage
  | ResizeSurfaceMessage
  | SetPolicyMessage
  | SetActiveDisplayMessage
  | DecodeMessage
  | DetachSurfaceMessage
  | CloseMessage;

type WorkerResponse =
  | { type: 'ready'; canDecode: boolean; reason?: string }
  | {
      type: 'frame';
      display: number;
      width: number;
      height: number;
      avgRenderMs: number;
      consecutiveSlowRenders: number;
      droppedBackpressure: number;
      droppedStale: number;
    }
  | { type: 'need_refresh'; display: number }
  | { type: 'log'; level: 'warn' | 'error'; message: string };

type DisplayPerf = {
  avgRenderMs: number;
  consecutiveSlowRenders: number;
  droppedBackpressure: number;
  droppedStale: number;
};

const CODEC_CONFIG: Record<CodecType, string[]> = {
  vp9: ['vp09.00.10.08'],
  av1: ['av01.0.08M.08', 'av01.0.04M.08'],
  h264: ['avc1.42E01E', 'avc1.4D401E', 'avc1.64001F'],
  h265: [
    'hvc1.1.6.L93.B0',
    'hvc1.1.6.L120.B0',
    'hev1.1.6.L93.B0',
    'hev1.1.6.L120.B0'
  ]
};
const BACKPRESSURE_KEYFRAME_TRIGGER_OVERFLOWS = 2;
const BACKPRESSURE_OVERFLOW_WINDOW_MS = 1800;

const decoders = new Map<string, VideoDecoder>();
const decoderConfigCache = new Map<CodecType, VideoDecoderConfig>();
const decoderBooting = new Map<string, Promise<VideoDecoder | null>>();
const decoderNeedsKeyFrame = new Map<string, boolean>();
const decoderLastPts = new Map<string, number>();
const decoderBackpressureOverflowState = new Map<string, { count: number; at: number }>();
const decodeErrorSuppressed = new Map<string, number>();
const decodeErrorLastLogAt = new Map<string, number>();
const needRefreshLastSentAt = new Map<string, number>();
const pendingFrames = new Map<number, VideoFrame>();
const renderScheduled = new Set<number>();
const displayPerf = new Map<number, DisplayPerf>();
const notifiedFrameSize = new Map<number, string>();
const lastPerfReportAt = new Map<number, number>();

let surfaceCanvas: OffscreenCanvas | null = null;
let surfaceContext: OffscreenCanvasRenderingContext2D | null = null;
let isClosed = false;
let lastQueueOverflowLogMs = 0;
let renderQualityPreference: 'low' | 'balanced' | 'best' | 'custom' = 'balanced';
let customImageQuality = 100;
let customFps = 60;
let activeDisplay: number | null = null;

const workerSelf = self as any;
const workerCapabilities = {
  videoDecoder: typeof VideoDecoder !== 'undefined',
  encodedVideoChunk: typeof EncodedVideoChunk !== 'undefined',
  offscreenCanvas: typeof OffscreenCanvas !== 'undefined'
};

const readyMessage: WorkerResponse = {
  type: 'ready',
  canDecode:
    workerCapabilities.videoDecoder &&
    workerCapabilities.encodedVideoChunk &&
    workerCapabilities.offscreenCanvas,
  reason:
    workerCapabilities.videoDecoder &&
    workerCapabilities.encodedVideoChunk &&
    workerCapabilities.offscreenCanvas
      ? undefined
      : 'Worker missing WebCodecs/OffscreenCanvas support'
};
workerSelf.postMessage(readyMessage);

workerSelf.onmessage = (event: { data: WorkerRequest }) => {
  if (isClosed) {
    return;
  }
  const message = event.data;
  if (!message || typeof message !== 'object') {
    return;
  }
  switch (message.type) {
    case 'attach_surface':
      attachSurface(message.canvas, message.width, message.height);
      break;
    case 'resize_surface':
      resizeSurface(message.width, message.height);
      break;
    case 'set_policy':
      renderQualityPreference = normalizeRenderQualityPreference(message.renderQuality);
      if (Number.isFinite(message.customQuality) && Number(message.customQuality) > 0) {
        customImageQuality = Math.round(
          clampNumber(Number(message.customQuality), 10, 2000)
        );
      }
      if (Number.isFinite(message.customFps) && Number(message.customFps) > 0) {
        customFps = Math.round(clampNumber(Number(message.customFps), 5, 120));
      }
      break;
    case 'set_active_display':
      setActiveDisplay(message.display, Boolean(message.reset));
      break;
    case 'decode':
      void decodeVideo(message);
      break;
    case 'detach_surface':
      detachSurface();
      break;
    case 'close':
      closeWorker();
      break;
    default:
      break;
  }
};

function attachSurface(canvas: OffscreenCanvas, width: number, height: number): void {
  surfaceCanvas = canvas;
  surfaceCanvas.width = clampSize(width);
  surfaceCanvas.height = clampSize(height);
  const ctx = surfaceCanvas.getContext('2d', {
    alpha: false,
    desynchronized: true
  });
  if (!ctx) {
    postLog('error', 'Worker surface context initialization failed');
    surfaceContext = null;
    return;
  }
  surfaceContext = ctx;
}

function resizeSurface(width: number, height: number): void {
  if (!surfaceCanvas || !surfaceContext) {
    return;
  }
  const nextWidth = clampSize(width);
  const nextHeight = clampSize(height);
  if (surfaceCanvas.width !== nextWidth || surfaceCanvas.height !== nextHeight) {
    const snapshot = captureSurfaceSnapshot(surfaceCanvas);
    surfaceCanvas.width = nextWidth;
    surfaceCanvas.height = nextHeight;
    restoreSurfaceSnapshot(snapshot, nextWidth, nextHeight);
  }
}

function captureSurfaceSnapshot(source: OffscreenCanvas): OffscreenCanvas | null {
  const width = clampSize(source.width);
  const height = clampSize(source.height);
  if (width <= 0 || height <= 0) {
    return null;
  }
  const snapshot = new OffscreenCanvas(width, height);
  const ctx = snapshot.getContext('2d', {
    alpha: false,
    desynchronized: true
  });
  if (!ctx) {
    return null;
  }
  ctx.drawImage(source, 0, 0, width, height);
  return snapshot;
}

function restoreSurfaceSnapshot(
  snapshot: OffscreenCanvas | null,
  targetWidth: number,
  targetHeight: number
): void {
  if (!snapshot || !surfaceContext || targetWidth <= 0 || targetHeight <= 0) {
    return;
  }
  applySamplingPolicy(
    surfaceContext,
    Math.max(1, snapshot.width || targetWidth),
    Math.max(1, snapshot.height || targetHeight),
    targetWidth,
    targetHeight
  );
  surfaceContext.clearRect(0, 0, targetWidth, targetHeight);
  surfaceContext.drawImage(snapshot, 0, 0, targetWidth, targetHeight);
}

async function decodeVideo(message: DecodeMessage): Promise<void> {
  if (!workerCapabilities.videoDecoder || !workerCapabilities.encodedVideoChunk) {
    return;
  }
  if (!surfaceCanvas || !surfaceContext) {
    return;
  }
  if (!shouldRenderDisplay(message.display)) {
    return;
  }
  const decoder = await getDecoder(message.codec, message.display);
  if (!decoder) {
    return;
  }
  const key = decoderKey(message.display, message.codec);
  if (message.data.byteLength === 0) {
    return;
  }
  if (shouldDropFrame(message.display, message.codec, decoder, message.key, key)) {
    return;
  }
  const chunk = new EncodedVideoChunk({
    type: message.key ? 'key' : 'delta',
    timestamp: normalizeTimestamp(key, message.pts),
    data: message.data
  });
  try {
    decoder.decode(chunk);
  } catch (err) {
    decoderNeedsKeyFrame.set(key, true);
    needRefreshLastSentAt.delete(key);
    requestRefresh(message.display, key);
    postDecodeError(key, err);
  }
}

function shouldDropFrame(
  display: number,
  _codec: CodecType,
  decoder: VideoDecoder,
  key: boolean,
  decoderStateKey: string
): boolean {
  const needsKey = decoderNeedsKeyFrame.get(decoderStateKey) !== false;
  if (needsKey) {
    if (!key) {
      requestRefresh(display, decoderStateKey);
      return true;
    }
    decoderNeedsKeyFrame.set(decoderStateKey, false);
    decoderBackpressureOverflowState.delete(decoderStateKey);
    needRefreshLastSentAt.delete(decoderStateKey);
  }
  if (key) {
    decoderBackpressureOverflowState.delete(decoderStateKey);
    return false;
  }
  const queueSize = decoder.decodeQueueSize;
  const dropThreshold = getDecodeQueueDropThreshold(
    renderQualityPreference,
    customImageQuality,
    customFps
  );
  if (queueSize <= dropThreshold) {
    coolDownBackpressureState(decoderStateKey);
    return false;
  }
  const now = Date.now();
  const prev = decoderBackpressureOverflowState.get(decoderStateKey);
  const overflowCount =
    prev && now - prev.at < BACKPRESSURE_OVERFLOW_WINDOW_MS ? prev.count + 1 : 1;
  decoderBackpressureOverflowState.set(decoderStateKey, {
    count: overflowCount,
    at: now
  });
  markDisplayBackpressureDrop(display);
  if (overflowCount < BACKPRESSURE_KEYFRAME_TRIGGER_OVERFLOWS) {
    return true;
  }
  decoderBackpressureOverflowState.delete(decoderStateKey);
  decoderNeedsKeyFrame.set(decoderStateKey, true);
  needRefreshLastSentAt.delete(decoderStateKey);
  requestRefresh(display, decoderStateKey);
  if (now - lastQueueOverflowLogMs > 1500) {
    lastQueueOverflowLogMs = now;
    postLog(
      'warn',
      `Worker decoder queue overflow (${queueSize}>${dropThreshold}) on display ${display}`
    );
  }
  return true;
}

function coolDownBackpressureState(decoderStateKey: string): void {
  const state = decoderBackpressureOverflowState.get(decoderStateKey);
  if (!state) {
    return;
  }
  if (state.count <= 1) {
    decoderBackpressureOverflowState.delete(decoderStateKey);
    return;
  }
  decoderBackpressureOverflowState.set(decoderStateKey, {
    count: state.count - 1,
    at: Date.now()
  });
}

async function getDecoder(codec: CodecType, display: number): Promise<VideoDecoder | null> {
  const key = decoderKey(display, codec);
  const existing = decoders.get(key);
  if (existing) {
    return existing;
  }
  const booting = decoderBooting.get(key);
  if (booting) {
    return booting;
  }
  clearDisplayCodecState(display, codec);
  const task = createDecoder(codec, display);
  decoderBooting.set(key, task);
  const decoder = await task;
  decoderBooting.delete(key);
  if (decoder && !shouldRenderDisplay(display)) {
    try {
      decoder.close();
    } catch {
      // ignore
    }
    return null;
  }
  if (decoder) {
    decoders.set(key, decoder);
  }
  return decoder;
}

async function createDecoder(codec: CodecType, display: number): Promise<VideoDecoder | null> {
  const config = await pickConfig(codec);
  if (!config) {
    return null;
  }
  const key = decoderKey(display, codec);
  const decoder = new VideoDecoder({
    output: (frame) => handleFrame(display, frame),
    error: (err) => {
      decoderNeedsKeyFrame.set(key, true);
      needRefreshLastSentAt.delete(key);
      requestRefresh(display, key);
      postLog('warn', `Worker decoder error${formatError(err)}`);
    }
  });
  try {
    decoder.configure(config);
    decoderNeedsKeyFrame.set(key, true);
    needRefreshLastSentAt.delete(key);
    decoderLastPts.delete(key);
    decodeErrorSuppressed.delete(key);
    decodeErrorLastLogAt.delete(key);
    return decoder;
  } catch {
    postLog('warn', `Worker decoder configure failed for ${codec}`);
    try {
      decoder.close();
    } catch {
      // ignore
    }
    return null;
  }
}

async function pickConfig(codec: CodecType): Promise<VideoDecoderConfig | null> {
  const cached = decoderConfigCache.get(codec);
  if (cached) {
    return cached;
  }
  for (const candidate of CODEC_CONFIG[codec]) {
    try {
      const support = await VideoDecoder.isConfigSupported({
        codec: candidate,
        optimizeForLatency: true,
        hardwareAcceleration: 'prefer-hardware'
      });
      if (support.supported) {
        const config: VideoDecoderConfig = {
          codec:
            support.config && typeof support.config.codec === 'string'
              ? support.config.codec
              : candidate,
          optimizeForLatency: true,
          hardwareAcceleration: 'prefer-hardware'
        };
        decoderConfigCache.set(codec, config);
        return config;
      }
    } catch {
      // ignore
    }
    try {
      const support = await VideoDecoder.isConfigSupported({
        codec: candidate,
        optimizeForLatency: true
      });
      if (support.supported) {
        const config: VideoDecoderConfig = {
          codec:
            support.config && typeof support.config.codec === 'string'
              ? support.config.codec
              : candidate,
          optimizeForLatency: true
        };
        decoderConfigCache.set(codec, config);
        return config;
      }
    } catch {
      // ignore
    }
  }
  postLog('warn', `No worker codec config available for ${codec}`);
  return null;
}

function handleFrame(display: number, frame: VideoFrame): void {
  if (!shouldRenderDisplay(display)) {
    frame.close();
    return;
  }
  const old = pendingFrames.get(display);
  if (old) {
    markDisplayStaleDrop(display);
    old.close();
  }
  pendingFrames.set(display, frame);
  if (renderScheduled.has(display)) {
    return;
  }
  renderScheduled.add(display);
  scheduleRender(() => {
    renderScheduled.delete(display);
    const latest = pendingFrames.get(display);
    if (!latest) {
      return;
    }
    pendingFrames.delete(display);
    renderFrame(display, latest);
  });
}

function renderFrame(display: number, frame: VideoFrame): void {
  const start = nowMs();
  try {
    if (!surfaceCanvas || !surfaceContext || !shouldRenderDisplay(display)) {
      return;
    }
    const width = frame.displayWidth;
    const height = frame.displayHeight;
    if (width <= 0 || height <= 0) {
      return;
    }
    applySamplingPolicy(surfaceContext, width, height, surfaceCanvas.width, surfaceCanvas.height);
    surfaceContext.clearRect(0, 0, surfaceCanvas.width, surfaceCanvas.height);
    surfaceContext.drawImage(frame, 0, 0, surfaceCanvas.width, surfaceCanvas.height);
    notifyFrame(display, width, height);
  } catch {
    postLog('warn', 'Worker render failed');
  } finally {
    recordRenderCost(display, nowMs() - start);
    frame.close();
  }
}

function notifyFrame(display: number, width: number, height: number): void {
  const key = `${width}x${height}`;
  const sizeChanged = notifiedFrameSize.get(display) !== key;
  if (sizeChanged) {
    notifiedFrameSize.set(display, key);
  }
  const now = Date.now();
  const lastReport = lastPerfReportAt.get(display) ?? 0;
  const perfDue = now - lastReport >= 1200;
  if (!sizeChanged && !perfDue) {
    return;
  }
  if (perfDue) {
    lastPerfReportAt.set(display, now);
  }
  const perf = getDisplayPerf(display);
  const payload: WorkerResponse = {
    type: 'frame',
    display,
    width,
    height,
    avgRenderMs: perf.avgRenderMs,
    consecutiveSlowRenders: perf.consecutiveSlowRenders,
    droppedBackpressure: perf.droppedBackpressure,
    droppedStale: perf.droppedStale
  };
  workerSelf.postMessage(payload);
}

function recordRenderCost(display: number, renderMs: number): void {
  if (!Number.isFinite(renderMs) || renderMs < 0) {
    return;
  }
  const perf = getDisplayPerf(display);
  if (perf.avgRenderMs === 0) {
    perf.avgRenderMs = renderMs;
  } else {
    perf.avgRenderMs = perf.avgRenderMs * 0.85 + renderMs * 0.15;
  }
  if (renderMs > 24) {
    perf.consecutiveSlowRenders = Math.min(10, perf.consecutiveSlowRenders + 1);
  } else if (perf.consecutiveSlowRenders > 0) {
    perf.consecutiveSlowRenders -= 1;
  }
}

function getDisplayPerf(display: number): DisplayPerf {
  const existing = displayPerf.get(display);
  if (existing) {
    return existing;
  }
  const perf: DisplayPerf = {
    avgRenderMs: 0,
    consecutiveSlowRenders: 0,
    droppedBackpressure: 0,
    droppedStale: 0
  };
  displayPerf.set(display, perf);
  return perf;
}

function markDisplayBackpressureDrop(display: number): void {
  const perf = getDisplayPerf(display);
  perf.droppedBackpressure += 1;
}

function markDisplayStaleDrop(display: number): void {
  const perf = getDisplayPerf(display);
  perf.droppedStale += 1;
}

function decoderKey(display: number, codec: CodecType): string {
  return `${display}:${codec}`;
}

function clearDisplayCodecState(display: number, keepCodec?: CodecType): void {
  const keepKey = keepCodec ? decoderKey(display, keepCodec) : '';
  const prefix = `${display}:`;
  for (const [key, decoder] of decoders.entries()) {
    if (!key.startsWith(prefix) || key === keepKey) {
      continue;
    }
    try {
      decoder.close();
    } catch {
      // ignore
    }
    decoders.delete(key);
    decoderBooting.delete(key);
    decoderNeedsKeyFrame.delete(key);
    decoderLastPts.delete(key);
    decoderBackpressureOverflowState.delete(key);
    decodeErrorSuppressed.delete(key);
    decodeErrorLastLogAt.delete(key);
    needRefreshLastSentAt.delete(key);
  }
  for (const key of [...decoderBooting.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      decoderBooting.delete(key);
    }
  }
  for (const key of [...decoderNeedsKeyFrame.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      decoderNeedsKeyFrame.delete(key);
    }
  }
  for (const key of [...decoderLastPts.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      decoderLastPts.delete(key);
    }
  }
  for (const key of [...decoderBackpressureOverflowState.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      decoderBackpressureOverflowState.delete(key);
    }
  }
  for (const key of [...decodeErrorSuppressed.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      decodeErrorSuppressed.delete(key);
    }
  }
  for (const key of [...decodeErrorLastLogAt.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      decodeErrorLastLogAt.delete(key);
    }
  }
  for (const key of [...needRefreshLastSentAt.keys()]) {
    if (key.startsWith(prefix) && key !== keepKey) {
      needRefreshLastSentAt.delete(key);
    }
  }
}

function clearPendingFrame(display: number): void {
  const frame = pendingFrames.get(display);
  if (frame) {
    frame.close();
    pendingFrames.delete(display);
  }
  renderScheduled.delete(display);
}

function resetDisplayState(display: number): void {
  clearPendingFrame(display);
  clearDisplayCodecState(display);
  displayPerf.delete(display);
  notifiedFrameSize.delete(display);
  lastPerfReportAt.delete(display);
}

function clearInactiveDisplayState(targetDisplay: number): void {
  for (const display of [...pendingFrames.keys()]) {
    if (display !== targetDisplay) {
      clearPendingFrame(display);
    }
  }
  for (const display of [...displayPerf.keys()]) {
    if (display !== targetDisplay) {
      displayPerf.delete(display);
    }
  }
  for (const display of [...notifiedFrameSize.keys()]) {
    if (display !== targetDisplay) {
      notifiedFrameSize.delete(display);
    }
  }
  for (const display of [...lastPerfReportAt.keys()]) {
    if (display !== targetDisplay) {
      lastPerfReportAt.delete(display);
    }
  }
  const prefix = `${targetDisplay}:`;
  for (const [key, decoder] of decoders.entries()) {
    if (key.startsWith(prefix)) {
      continue;
    }
    try {
      decoder.close();
    } catch {
      // ignore
    }
    decoders.delete(key);
    decoderBooting.delete(key);
    decoderNeedsKeyFrame.delete(key);
    decoderLastPts.delete(key);
    decoderBackpressureOverflowState.delete(key);
    decodeErrorSuppressed.delete(key);
    decodeErrorLastLogAt.delete(key);
    needRefreshLastSentAt.delete(key);
  }
  for (const key of [...decoderBooting.keys()]) {
    if (!key.startsWith(prefix)) {
      decoderBooting.delete(key);
    }
  }
  for (const key of [...decoderNeedsKeyFrame.keys()]) {
    if (!key.startsWith(prefix)) {
      decoderNeedsKeyFrame.delete(key);
    }
  }
  for (const key of [...decoderLastPts.keys()]) {
    if (!key.startsWith(prefix)) {
      decoderLastPts.delete(key);
    }
  }
  for (const key of [...decoderBackpressureOverflowState.keys()]) {
    if (!key.startsWith(prefix)) {
      decoderBackpressureOverflowState.delete(key);
    }
  }
  for (const key of [...decodeErrorSuppressed.keys()]) {
    if (!key.startsWith(prefix)) {
      decodeErrorSuppressed.delete(key);
    }
  }
  for (const key of [...decodeErrorLastLogAt.keys()]) {
    if (!key.startsWith(prefix)) {
      decodeErrorLastLogAt.delete(key);
    }
  }
  for (const key of [...needRefreshLastSentAt.keys()]) {
    if (!key.startsWith(prefix)) {
      needRefreshLastSentAt.delete(key);
    }
  }
}

function detachSurface(): void {
  surfaceContext = null;
  surfaceCanvas = null;
  notifiedFrameSize.clear();
  lastPerfReportAt.clear();
}

function closeWorker(): void {
  isClosed = true;
  for (const decoder of decoders.values()) {
    try {
      decoder.close();
    } catch {
      // ignore
    }
  }
  for (const frame of pendingFrames.values()) {
    frame.close();
  }
  decoders.clear();
  decoderBooting.clear();
  decoderConfigCache.clear();
  decoderNeedsKeyFrame.clear();
  decoderLastPts.clear();
  decoderBackpressureOverflowState.clear();
  decodeErrorSuppressed.clear();
  decodeErrorLastLogAt.clear();
  needRefreshLastSentAt.clear();
  pendingFrames.clear();
  renderScheduled.clear();
  displayPerf.clear();
  notifiedFrameSize.clear();
  lastPerfReportAt.clear();
  surfaceContext = null;
  surfaceCanvas = null;
}

function requestRefresh(display: number, decoderStateKey: string): void {
  if (!shouldRenderDisplay(display)) {
    return;
  }
  const now = Date.now();
  const last = needRefreshLastSentAt.get(decoderStateKey) ?? 0;
  if (now - last < 900) {
    return;
  }
  needRefreshLastSentAt.set(decoderStateKey, now);
  const payload: WorkerResponse = {
    type: 'need_refresh',
    display
  };
  workerSelf.postMessage(payload);
}

function normalizeDisplay(display: number): number | null {
  const normalized = Math.floor(Number(display));
  if (!Number.isFinite(normalized) || normalized < 0) {
    return null;
  }
  return normalized;
}

function shouldRenderDisplay(display: number): boolean {
  const normalized = normalizeDisplay(display);
  return activeDisplay === null || normalized === activeDisplay;
}

function setActiveDisplay(display: number, reset: boolean): void {
  const normalized = normalizeDisplay(display);
  activeDisplay = normalized;
  if (normalized === null) {
    return;
  }
  clearInactiveDisplayState(normalized);
  if (reset) {
    resetDisplayState(normalized);
  }
}

function normalizeTimestamp(key: string, pts: number): number {
  const last = decoderLastPts.get(key);
  let next = Number.isFinite(pts) ? Math.floor(pts) : 0;
  if (!Number.isFinite(next) || next < 0) {
    next = last !== undefined ? last + 1 : 0;
  }
  if (last !== undefined && next <= last) {
    next = last + 1;
  }
  decoderLastPts.set(key, next);
  return next;
}

function postDecodeError(key: string, err: unknown): void {
  const now = Date.now();
  const last = decodeErrorLastLogAt.get(key) ?? 0;
  const suppressed = decodeErrorSuppressed.get(key) ?? 0;
  if (now - last > 3000) {
    decodeErrorLastLogAt.set(key, now);
    decodeErrorSuppressed.set(key, 0);
    if (suppressed > 0) {
      postLog(
        'warn',
        `Worker decode failed [${key}] (${suppressed} suppressed)${formatError(err)}`
      );
    } else {
      postLog('warn', `Worker decode failed [${key}]${formatError(err)}`);
    }
    return;
  }
  decodeErrorSuppressed.set(key, suppressed + 1);
}

function clampSize(value: number): number {
  const rounded = Math.floor(value);
  if (!Number.isFinite(rounded) || rounded < 1) {
    return 1;
  }
  return rounded;
}

function applySamplingPolicy(
  ctx: OffscreenCanvasRenderingContext2D,
  sourceWidth: number,
  sourceHeight: number,
  targetWidth: number,
  targetHeight: number
): void {
  const downscale = targetWidth + 1 < sourceWidth || targetHeight + 1 < sourceHeight;
  const upscale = targetWidth > sourceWidth + 1 || targetHeight > sourceHeight + 1;
  const enableSmoothing = downscale || upscale;
  if (ctx.imageSmoothingEnabled !== enableSmoothing) {
    ctx.imageSmoothingEnabled = enableSmoothing;
  }
  if (enableSmoothing && 'imageSmoothingQuality' in ctx) {
    const quality: ImageSmoothingQuality = downscale ? 'high' : 'medium';
    if ((ctx as any).imageSmoothingQuality !== quality) {
      (ctx as any).imageSmoothingQuality = quality;
    }
  }
}

function postLog(level: 'warn' | 'error', message: string): void {
  const payload: WorkerResponse = { type: 'log', level, message };
  workerSelf.postMessage(payload);
}

function formatError(err: unknown): string {
  if (err instanceof Error && err.message) {
    return `: ${err.message}`;
  }
  if (typeof err === 'string' && err.trim().length > 0) {
    return `: ${err.trim()}`;
  }
  return '';
}

function nowMs(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}

function scheduleRender(cb: () => void): void {
  if (typeof workerSelf.requestAnimationFrame === 'function') {
    workerSelf.requestAnimationFrame(() => cb());
    return;
  }
  setTimeout(cb, 0);
}

function getDecodeQueueDropThreshold(
  quality: 'low' | 'balanced' | 'best' | 'custom',
  customQuality: number,
  customFpsValue: number
): number {
  switch (quality) {
    case 'low':
      return 13;
    case 'best':
      return 20;
    case 'custom': {
      const qualityAdj = clampNumber(Math.round((customQuality - 100) / 100), -3, 6);
      const fpsAdj = clampNumber(Math.round((60 - customFpsValue) / 30), -2, 2);
      return Math.round(clampNumber(22 + qualityAdj + fpsAdj, 15, 30));
    }
    default:
      return 16;
  }
}

function normalizeRenderQualityPreference(
  value: unknown
): 'low' | 'balanced' | 'best' | 'custom' {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (normalized === 'low') {
    return 'low';
  }
  if (normalized === 'best') {
    return 'best';
  }
  if (normalized === 'custom') {
    return 'custom';
  }
  return 'balanced';
}

function clampNumber(value: number, minValue: number, maxValue: number): number {
  if (!Number.isFinite(value)) {
    return minValue;
  }
  if (value < minValue) {
    return minValue;
  }
  if (value > maxValue) {
    return maxValue;
  }
  return value;
}
