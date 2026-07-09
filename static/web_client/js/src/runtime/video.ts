import { Logger } from '../core/logger';

export type CodecType = 'vp8' | 'vp9' | 'av1' | 'h264' | 'h265';
export type RenderQualityPreference = 'low' | 'balanced' | 'best' | 'custom';
export type DecodingSupport = {
  vp8: boolean;
  vp9: boolean;
  av1: boolean;
  h264: boolean;
  h265: boolean;
};

type DecodeInput = {
  codec: CodecType;
  display: number;
  data: Uint8Array;
  key: boolean;
  pts?: number | string;
};

type RgbaSink = (
  display: number,
  rgba: Uint8Array,
  width: number,
  height: number
) => void;
type DecodedFrameSink = (display: number, width: number, height: number) => void;
type NeedRefreshSink = (display: number) => void;

type Canvas2dContext = CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;
type DirectCanvasContext = CanvasRenderingContext2D;
type DisplayPerf = {
  avgRenderMs: number;
  consecutiveSlowRenders: number;
  droppedBackpressure: number;
  droppedStale: number;
};
type WorkerFrameMessage = {
  type: 'frame';
  display: number;
  width: number;
  height: number;
  avgRenderMs?: number;
  consecutiveSlowRenders?: number;
  droppedBackpressure?: number;
  droppedStale?: number;
};
type WorkerReadyMessage = {
  type: 'ready';
  canDecode: boolean;
  reason?: string;
};
type WorkerLogMessage = {
  type: 'log';
  level: 'warn' | 'error';
  message: string;
};
type WorkerNeedRefreshMessage = {
  type: 'need_refresh';
  display: number;
};
type WorkerSetActiveDisplayMessage = {
  type: 'set_active_display';
  display: number;
  reset?: boolean;
};
type WorkerMessage =
  | WorkerReadyMessage
  | WorkerFrameMessage
  | WorkerNeedRefreshMessage
  | WorkerLogMessage;
type WorkerMode = 'module' | 'classic';
type RenderQualityProfile = {
  dprCapDefault: number;
  dprCapFullHd: number;
  dprCapQhd: number;
  dprCapMediumLoad: number;
  dprCapHeavyLoad: number;
  pixelBudgetDefault: number;
  pixelBudgetQhd: number;
};
type AdaptiveRenderScaleBounds = {
  minBudgetScale: number;
  maxBudgetScale: number;
  minDprScale: number;
  maxDprScale: number;
};
type AdaptiveRenderState = {
  budgetScale: number;
  dprScale: number;
  lastAdjustMs: number;
  lastEvalMs: number;
  lastBackpressureDrops: number;
  lastStaleDrops: number;
  stressEma: number;
  badWindows: number;
  goodWindows: number;
  pendingDownscaleConfirmations: number;
};
type DisplayGeometry = {
  width: number;
  height: number;
};
type OgvFramePlane = {
  bytes: Uint8Array;
  stride: number;
};
type OgvFrameFormat = {
  width: number;
  height: number;
  chromaWidth: number;
  chromaHeight: number;
  cropLeft: number;
  cropTop: number;
  cropWidth: number;
  cropHeight: number;
  displayWidth: number;
  displayHeight: number;
};
type OgvFrameBuffer = {
  format: OgvFrameFormat;
  y: OgvFramePlane;
  u: OgvFramePlane;
  v: OgvFramePlane;
};
type OgvDecoderModule = {
  init: (done: () => void) => void;
  processFrame: (data: ArrayBuffer, done: (ok: boolean) => void) => void;
  close: () => void;
  frameBuffer: OgvFrameBuffer | null;
  recycleFrame?: (frame: OgvFrameBuffer) => void;
};
type SoftwareDecoderConfig = {
  globalName: 'OGVDecoderVideoVP8W' | 'OGVDecoderVideoVP9W' | 'OGVDecoderVideoAV1W';
  scriptName:
    | 'ogv-decoder-video-vp8-wasm.js'
    | 'ogv-decoder-video-vp9-wasm.js'
    | 'ogv-decoder-video-av1-wasm.js';
};

const CODEC_CONFIG: Record<CodecType, string[]> = {
  vp8: ['vp8'],
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
const SOFTWARE_DECODER_CONFIG: Partial<Record<CodecType, SoftwareDecoderConfig>> = {
  vp8: {
    globalName: 'OGVDecoderVideoVP8W',
    scriptName: 'ogv-decoder-video-vp8-wasm.js'
  },
  vp9: {
    globalName: 'OGVDecoderVideoVP9W',
    scriptName: 'ogv-decoder-video-vp9-wasm.js'
  },
  av1: {
    globalName: 'OGVDecoderVideoAV1W',
    scriptName: 'ogv-decoder-video-av1-wasm.js'
  }
};
const SOFTWARE_DECODER_SOURCES = new Map<CodecType, Promise<string>>();
const SOFTWARE_DECODER_AVAILABILITY = new Map<CodecType, Promise<boolean>>();

const RENDER_QUALITY_PROFILES: Record<RenderQualityPreference, RenderQualityProfile> = {
  low: {
    dprCapDefault: 1.08,
    dprCapFullHd: 0.95,
    dprCapQhd: 0.85,
    dprCapMediumLoad: 0.88,
    dprCapHeavyLoad: 0.76,
    pixelBudgetDefault: 1408 * 792,
    pixelBudgetQhd: 1184 * 666
  },
  balanced: {
    dprCapDefault: 2.05,
    dprCapFullHd: 1.75,
    dprCapQhd: 1.4,
    dprCapMediumLoad: 1.55,
    dprCapHeavyLoad: 1.25,
    pixelBudgetDefault: 2880 * 1620,
    pixelBudgetQhd: 2560 * 1440
  },
  best: {
    dprCapDefault: 2.35,
    dprCapFullHd: 2.0,
    dprCapQhd: 1.6,
    dprCapMediumLoad: 1.75,
    dprCapHeavyLoad: 1.35,
    pixelBudgetDefault: 3456 * 1944,
    pixelBudgetQhd: 3072 * 1728
  },
  // Custom is computed dynamically from user quality/fps in getActiveRenderProfile().
  custom: {
    dprCapDefault: 2.35,
    dprCapFullHd: 2.0,
    dprCapQhd: 1.6,
    dprCapMediumLoad: 1.75,
    dprCapHeavyLoad: 1.35,
    pixelBudgetDefault: 3456 * 1944,
    pixelBudgetQhd: 3072 * 1728
  }
};
const ADAPTIVE_RENDER_SCALE_BOUNDS: Record<
  RenderQualityPreference,
  AdaptiveRenderScaleBounds
> = {
  low: {
    minBudgetScale: 0.72,
    maxBudgetScale: 1.0,
    minDprScale: 0.84,
    maxDprScale: 1.0
  },
  balanced: {
    minBudgetScale: 0.94,
    maxBudgetScale: 1.45,
    minDprScale: 0.97,
    maxDprScale: 1.28
  },
  best: {
    minBudgetScale: 0.97,
    maxBudgetScale: 1.68,
    minDprScale: 1.0,
    maxDprScale: 1.42
  },
  custom: {
    minBudgetScale: 0.98,
    maxBudgetScale: 1.8,
    minDprScale: 1.0,
    maxDprScale: 1.5
  }
};
const ADAPTIVE_RENDER_STARTUP_GRACE_MS = 3600;
const ADAPTIVE_EVAL_MIN_INTERVAL_MS = 1100;
const ADAPTIVE_DECREASE_COOLDOWN_MS = 1600;
const ADAPTIVE_INCREASE_COOLDOWN_MS = 5200;
const ADAPTIVE_RECOVERY_COOLDOWN_MS = 8600;
const ADAPTIVE_DECREASE_CONFIRMATION_COUNT = 2;
const BACKPRESSURE_KEYFRAME_TRIGGER_OVERFLOWS = 2;
const BACKPRESSURE_OVERFLOW_WINDOW_MS = 1800;

export class VideoPipeline {
  private readonly logger = new Logger('video');
  private readonly decoders = new Map<string, VideoDecoder>();
  private readonly softwareDecoders = new Map<string, Promise<SoftwareDecoder>>();
  private readonly decoderConfigCache = new Map<CodecType, VideoDecoderConfig>();
  private readonly decoderBooting = new Map<string, Promise<void>>();
  private readonly pendingDecodeInputs = new Map<string, DecodeInput[]>();
  private readonly decoderNeedsKeyFrame = new Map<string, boolean>();
  private readonly decoderLastPts = new Map<string, number>();
  private readonly decoderBackpressureOverflowState = new Map<
    string,
    { count: number; at: number }
  >();
  private readonly needRefreshLastSentAt = new Map<string, number>();
  private readonly canvases = new Map<number, OffscreenCanvas | HTMLCanvasElement>();
  private readonly contexts = new Map<number, Canvas2dContext>();
  private readonly softwareSourceCanvases = new Map<number, OffscreenCanvas | HTMLCanvasElement>();
  private readonly pendingFrames = new Map<number, VideoFrame>();
  private readonly renderScheduled = new Set<number>();
  private readonly displayPerf = new Map<number, DisplayPerf>();
  private readonly adaptiveRenderState = new Map<number, AdaptiveRenderState>();
  private readonly adaptiveStartupUntil = new Map<number, number>();
  private readonly notifiedFrameSize = new Map<number, string>();
  private readonly lastFrameRenderedAt = new Map<number, number>();
  private readonly displayGeometries = new Map<number, DisplayGeometry>();
  private readonly sink: RgbaSink;
  private readonly onFrameDecoded?: DecodedFrameSink;
  private readonly onNeedRefresh?: NeedRefreshSink;
  private lastDecodeErrorLogMs = 0;
  private suppressedDecodeErrorCount = 0;
  private lastDecoderErrorLogMs = 0;
  private suppressedDecoderErrorCount = 0;
  private lastQueueOverflowLogMs = 0;
  private directSurfaceElementId = '';
  private directSurfaceHost: HTMLElement | null = null;
  private directSurfaceCanvas: HTMLCanvasElement | null = null;
  private directSurfaceContext: DirectCanvasContext | null = null;
  private directSurfaceResizeObserver: ResizeObserver | null = null;
  private directSurfaceWindowResizeListener: EventListener | null = null;
  private directSurfaceViewportResizeListener: EventListener | null = null;
  private directSurfaceActiveDisplay = 0;
  private directSurfaceCssWidth = 0;
  private directSurfaceCssHeight = 0;
  private directSurfaceNativeDpr = 1;
  private directSurfaceDpr = 1;
  private directSurfaceSourceWidth = 0;
  private directSurfaceSourceHeight = 0;
  private directSurfaceBackingWidth = 0;
  private directSurfaceBackingHeight = 0;
  private directSurfaceLastMeasureMs = 0;
  private directSurfaceViewportChanged = false;
  private directSurfaceViewportSyncHandle: number | undefined;
  private directSurfaceRecoveryTimer: number | undefined;
  private directSurfaceHardRecoveryTimer: number | undefined;
  private directSurfaceRecoveryDisplay: number | null = null;
  private directSurfaceRecoveryRequestedAt = 0;
  private renderQualityPreference: RenderQualityPreference = 'balanced';
  private customImageQuality = 100;
  private customFps = 60;
  private readonly workerSupported: boolean;
  private worker: Worker | null = null;
  private workerReady = false;
  private workerSurfaceAttached = false;
  private workerUnavailable = false;
  private directSurfaceUseWorker = false;
  private workerMode: WorkerMode | null = null;
  private workerInitTimer: number | undefined;
  private workerFallbackTried = false;
  private workerDecodeFailureWindowStart = 0;
  private workerDecodeFailureCount = 0;
  private activeDisplay: number | null = null;

  constructor(
    sink: RgbaSink,
    onFrameDecoded?: DecodedFrameSink,
    onNeedRefresh?: NeedRefreshSink
  ) {
    this.sink = sink;
    this.onFrameDecoded = onFrameDecoded;
    this.onNeedRefresh = onNeedRefresh;
    this.workerSupported = canUseVideoWorker();
  }

  attachSurface(elementId: string): void {
    const normalized = elementId.trim();
    if (!normalized) {
      return;
    }
    if (this.directSurfaceElementId === normalized && this.directSurfaceHost) {
      return;
    }
    this.releaseDirectSurface();
    this.directSurfaceElementId = normalized;
  }

  detachSurface(elementId?: string): void {
    const normalized = String(elementId ?? '').trim();
    if (normalized && normalized !== this.directSurfaceElementId) {
      return;
    }
    this.releaseDirectSurface();
    this.directSurfaceElementId = '';
  }

  setRenderQualityPreference(value: string): void {
    const next = normalizeRenderQualityPreference(value);
    if (next === this.renderQualityPreference) {
      return;
    }
    this.renderQualityPreference = next;
    this.adaptiveRenderState.clear();
    this.adaptiveStartupUntil.clear();
    this.measureDirectSurfaceHost(true);
    this.refreshDirectSurfaceSizing(true);
    this.syncWorkerRenderPolicy();
  }

  setCustomQualityTuning(customQuality?: number, customFps?: number): void {
    let changed = false;
    if (Number.isFinite(customQuality) && Number(customQuality) > 0) {
      const normalized = Math.round(clamp(Number(customQuality), 10, 2000));
      if (normalized !== this.customImageQuality) {
        this.customImageQuality = normalized;
        changed = true;
      }
    }
    if (Number.isFinite(customFps) && Number(customFps) > 0) {
      const normalized = Math.round(clamp(Number(customFps), 5, 120));
      if (normalized !== this.customFps) {
        this.customFps = normalized;
        changed = true;
      }
    }
    if (!changed) {
      return;
    }
    if (this.renderQualityPreference === 'custom') {
      this.measureDirectSurfaceHost(true);
      this.refreshDirectSurfaceSizing(true);
    }
    this.syncWorkerRenderPolicy();
  }

  decode(input: DecodeInput): void {
    if (!this.isActiveDisplay(input.display)) {
      return;
    }
    if (this.isSoftwareBackedCodec(input.codec) && this.directSurfaceUseWorker) {
      this.detachSurfaceFromWorker(true);
    }
    if (this.sendDecodeToWorker(input)) {
      return;
    }
    if (typeof VideoDecoder === 'undefined') {
      void this.decodeWithSoftwareFallback(input);
      return;
    }
    const key = this.decoderKey(input.display, input.codec);
    const decoder = this.decoders.get(key);
    if (decoder) {
      this.decodeWithDecoder(decoder, input);
      return;
    }
    this.enqueuePendingDecodeInput(key, input);
    if (this.decoderBooting.has(key)) {
      return;
    }
    const booting = this.ensureDecoder(input.codec, input.display)
      .then((ready) => {
        const buffered = this.pendingDecodeInputs.get(key) ?? [];
        this.pendingDecodeInputs.delete(key);
        if (!ready) {
          for (const entry of buffered) {
            void this.decodeWithSoftwareFallback(entry);
          }
          return;
        }
        if (!this.isActiveDisplay(input.display)) {
          try {
            ready.close();
          } catch {
            // ignore
          }
          this.decoders.delete(key);
          return;
        }
        for (const entry of buffered) {
          this.decodeWithDecoder(ready, entry);
        }
      })
      .catch((err) => {
        this.logger.error('Decoder bootstrap failed', err);
        this.pendingDecodeInputs.delete(key);
      })
      .finally(() => {
        this.decoderBooting.delete(key);
      });
    this.decoderBooting.set(key, booting);
  }

  close(): void {
    for (const decoder of this.decoders.values()) {
      decoder.close();
    }
    for (const frame of this.pendingFrames.values()) {
      frame.close();
    }
    this.decoders.clear();
    for (const decoder of this.softwareDecoders.values()) {
      void decoder.then((item) => item.close());
    }
    this.decoderBooting.clear();
    this.pendingDecodeInputs.clear();
    this.decoderNeedsKeyFrame.clear();
    this.decoderLastPts.clear();
    this.decoderBackpressureOverflowState.clear();
    this.needRefreshLastSentAt.clear();
    this.decoderConfigCache.clear();
    this.softwareDecoders.clear();
    this.canvases.clear();
    this.contexts.clear();
    this.softwareSourceCanvases.clear();
    this.pendingFrames.clear();
    this.renderScheduled.clear();
    this.displayPerf.clear();
    this.adaptiveRenderState.clear();
    this.adaptiveStartupUntil.clear();
    this.displayGeometries.clear();
    this.notifiedFrameSize.clear();
    this.detachSurface();
    this.shutdownWorker();
  }

  setDisplayGeometries(displays: Array<{ width: number; height: number }>): void {
    const next = new Map<number, DisplayGeometry>();
    displays.forEach((display, index) => {
      const width = Math.max(1, Math.floor(Number(display.width) || 0));
      const height = Math.max(1, Math.floor(Number(display.height) || 0));
      if (width > 0 && height > 0) {
        next.set(index, { width, height });
      }
    });
    let changed = this.displayGeometries.size !== next.size;
    if (!changed) {
      for (const [index, value] of next.entries()) {
        const previous = this.displayGeometries.get(index);
        if (!previous || previous.width !== value.width || previous.height !== value.height) {
          changed = true;
          break;
        }
      }
    }
    if (!changed) {
      return;
    }
    this.displayGeometries.clear();
    next.forEach((value, index) => {
      this.displayGeometries.set(index, value);
    });
    this.measureDirectSurfaceHost(true);
    this.refreshDirectSurfaceSizing(true);
  }

  setActiveDisplay(display: number | null): void {
    const normalized = this.normalizeDisplay(display);
    const changed = normalized !== this.activeDisplay;
    this.activeDisplay = normalized;
    if (normalized !== null) {
      this.directSurfaceActiveDisplay = normalized;
    }
    if (changed) {
      this.clearInactiveDisplayState(normalized);
    }
    this.syncWorkerActiveDisplay(false);
  }

  switchDisplay(display: number): void {
    const normalized = this.normalizeDisplay(display);
    if (normalized === null) {
      return;
    }
    this.activeDisplay = normalized;
    this.directSurfaceActiveDisplay = normalized;
    this.clearInactiveDisplayState(normalized);
    this.resetDisplayState(normalized);
    this.syncWorkerActiveDisplay(true);
  }

  private async ensureDecoder(codec: CodecType, display: number): Promise<VideoDecoder | null> {
    const key = this.decoderKey(display, codec);
    const existing = this.decoders.get(key);
    if (existing) {
      return existing;
    }
    this.clearDisplayCodecState(display, codec);
    const config = await this.pickConfig(codec);
    if (!config) {
      return null;
    }
    const decoder = new VideoDecoder({
      output: (frame) => this.handleFrame(display, frame),
      error: (err) => {
        this.decoderNeedsKeyFrame.set(key, true);
        this.needRefreshLastSentAt.delete(key);
        this.requestRefresh(display, key);
        this.logDecoderError(err);
      }
    });
    decoder.configure(config);
    this.decoderNeedsKeyFrame.set(key, true);
    this.needRefreshLastSentAt.delete(key);
    this.decoderLastPts.delete(key);
    this.decoders.set(key, decoder);
    return decoder;
  }

  private async pickConfig(codec: CodecType): Promise<VideoDecoderConfig | null> {
    const cached = this.decoderConfigCache.get(codec);
    if (cached) {
      return cached;
    }
    for (const candidate of CODEC_CONFIG[codec]) {
      try {
        const supported = await VideoDecoder.isConfigSupported({
          codec: candidate,
          optimizeForLatency: true,
          hardwareAcceleration: 'prefer-hardware'
        });
        if (supported.supported) {
          const picked = {
            codec:
              supported.config && typeof supported.config.codec === 'string'
                ? supported.config.codec
                : candidate,
            optimizeForLatency: true,
            hardwareAcceleration: 'prefer-hardware' as const
          };
          this.decoderConfigCache.set(codec, picked);
          return picked;
        }
      } catch (err) {
        this.logger.warn(`Hardware codec probe failed: ${candidate}`, err);
      }
      try {
        const supported = await VideoDecoder.isConfigSupported({
          codec: candidate,
          optimizeForLatency: true
        });
        if (supported.supported) {
          const picked = {
            codec:
              supported.config && typeof supported.config.codec === 'string'
                ? supported.config.codec
                : candidate,
            optimizeForLatency: true
          };
          this.decoderConfigCache.set(codec, picked);
          return picked;
        }
      } catch (err) {
        this.logger.warn(`Codec probe failed: ${candidate}`, err);
      }
    }
    this.logger.warn(`No supported codec found for ${codec}`);
    return null;
  }

  private async decodeWithSoftwareFallback(input: DecodeInput): Promise<void> {
    const key = this.decoderKey(input.display, input.codec);
    if (this.shouldWaitForKeyframe(key, input.display, input.key)) {
      return;
    }
    const softwareDecoder = await this.ensureSoftwareDecoder(
      input.codec,
      input.display
    );
    if (!softwareDecoder) {
      this.logger.error(`No video decoder available for ${input.codec}`);
      this.decoderNeedsKeyFrame.set(key, true);
      this.needRefreshLastSentAt.delete(key);
      this.requestRefresh(input.display, key);
      return;
    }
    if (!this.isActiveDisplay(input.display)) {
      softwareDecoder.close();
      this.softwareDecoders.delete(key);
      return;
    }
    const ok = await softwareDecoder.decode(input);
    if (!ok) {
      this.clearDisplayCodecState(input.display, input.codec);
      this.decoderNeedsKeyFrame.set(key, true);
      this.needRefreshLastSentAt.delete(key);
      this.requestRefresh(input.display, key);
    }
  }

  private async ensureSoftwareDecoder(
    codec: CodecType,
    display: number
  ): Promise<SoftwareDecoder | null> {
    if (!SOFTWARE_DECODER_CONFIG[codec]) {
      return null;
    }
    const key = this.decoderKey(display, codec);
    const existing = this.softwareDecoders.get(key);
    if (existing) {
      return existing;
    }
    this.clearDisplayCodecState(display, codec);
    this.decoderNeedsKeyFrame.set(key, true);
    this.needRefreshLastSentAt.delete(key);
    this.decoderLastPts.delete(key);
    const created = this.createSoftwareDecoder(codec, display);
    this.softwareDecoders.set(key, created);
    return created;
  }

  private async createSoftwareDecoder(
    codec: CodecType,
    display: number
  ): Promise<SoftwareDecoder> {
    const module = await instantiateSoftwareDecoder(codec);
    return new SoftwareDecoder(
      display,
      module,
      this.logger,
      (targetDisplay, rgba, width, height, displayWidth, displayHeight) =>
        this.renderSoftwareDecodedFrame(
          targetDisplay,
          rgba,
          width,
          height,
          displayWidth,
          displayHeight
        )
    );
  }

  private handleFrame(display: number, frame: VideoFrame): void {
    if (!this.isActiveDisplay(display)) {
      frame.close();
      return;
    }
    const old = this.pendingFrames.get(display);
    if (old) {
      this.markDisplayStaleDrop(display);
      old.close();
    }
    this.pendingFrames.set(display, frame);
    if (this.renderScheduled.has(display)) {
      return;
    }
    this.renderScheduled.add(display);
    this.scheduleRender(() => {
      this.renderScheduled.delete(display);
      const latest = this.pendingFrames.get(display);
      if (!latest) {
        return;
      }
      this.pendingFrames.delete(display);
      this.renderFrame(display, latest);
    });
  }

  private scheduleRender(cb: () => void): void {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => cb());
      return;
    }
    setTimeout(cb, 16);
  }

  private renderFrame(display: number, frame: VideoFrame): void {
    const start = nowMs();
    try {
      if (!this.isActiveDisplay(display)) {
        return;
      }
      const width = frame.displayWidth;
      const height = frame.displayHeight;
      if (width === 0 || height === 0) {
        return;
      }
      if (this.renderToDirectSurface(display, frame, width, height)) {
        this.notifyFrame(display, width, height);
        return;
      }
      const ctx = this.ensureContext(display, width, height);
      if (!ctx) {
        return;
      }
      ctx.drawImage(frame, 0, 0, width, height);
      const imageData = ctx.getImageData(0, 0, width, height);
      const rgba = new Uint8Array(
        imageData.data.buffer,
        imageData.data.byteOffset,
        imageData.data.byteLength
      );
      this.sink(display, rgba, width, height);
      this.notifyFrame(display, width, height);
    } catch (err) {
      this.logger.error('Failed to render video frame', err);
    } finally {
      this.recordRenderCost(display, nowMs() - start);
      frame.close();
    }
  }

  private notifyFrame(display: number, width: number, height: number): void {
    this.lastFrameRenderedAt.set(display, Date.now());
    this.maybeCompleteDirectSurfaceRecovery(display);
    if (!this.adaptiveStartupUntil.has(display)) {
      this.adaptiveStartupUntil.set(display, Date.now() + ADAPTIVE_RENDER_STARTUP_GRACE_MS);
      const adaptive = this.getAdaptiveRenderState(display);
      adaptive.budgetScale = 1;
      adaptive.dprScale = 1;
      adaptive.lastAdjustMs = 0;
      adaptive.badWindows = 0;
      adaptive.goodWindows = 0;
      adaptive.pendingDownscaleConfirmations = 0;
    }
    const sizeKey = `${width}x${height}`;
    if (this.onFrameDecoded) {
      this.onFrameDecoded(display, width, height);
    }
    if (this.notifiedFrameSize.get(display) === sizeKey) {
      return;
    }
    this.notifiedFrameSize.set(display, sizeKey);
    if (typeof window.onVideoFrame === 'function') {
      window.onVideoFrame(display, width, height);
    }
  }

  private ensureCanvas(
    display: number,
    width: number,
    height: number
  ): OffscreenCanvas | HTMLCanvasElement {
    const existing = this.canvases.get(display);
    if (existing) {
      if (existing.width !== width || existing.height !== height) {
        existing.width = width;
        existing.height = height;
      }
      return existing;
    }
    let canvas: OffscreenCanvas | HTMLCanvasElement;
    if (typeof OffscreenCanvas !== 'undefined') {
      canvas = new OffscreenCanvas(width, height);
    } else {
      const element = document.createElement('canvas');
      element.width = width;
      element.height = height;
      canvas = element;
    }
    this.canvases.set(display, canvas);
    return canvas;
  }

  private ensureContext(
    display: number,
    width: number,
    height: number
  ): Canvas2dContext | null {
    const canvas = this.ensureCanvas(display, width, height);
    const existing = this.contexts.get(display);
    if (existing) {
      return existing;
    }
    const ctx = canvas.getContext('2d', {
      alpha: false,
      desynchronized: true,
      willReadFrequently: true
    });
    if (!ctx || !isCanvas2dContext(ctx)) {
      return null;
    }
    ctx.imageSmoothingEnabled = false;
    this.contexts.set(display, ctx);
    return ctx;
  }

  private ensureSoftwareSourceCanvas(
    display: number,
    width: number,
    height: number
  ): OffscreenCanvas | HTMLCanvasElement {
    const existing = this.softwareSourceCanvases.get(display);
    if (existing) {
      if (existing.width !== width || existing.height !== height) {
        existing.width = width;
        existing.height = height;
      }
      return existing;
    }
    let canvas: OffscreenCanvas | HTMLCanvasElement;
    if (typeof OffscreenCanvas !== 'undefined') {
      canvas = new OffscreenCanvas(width, height);
    } else {
      const element = document.createElement('canvas');
      element.width = width;
      element.height = height;
      canvas = element;
    }
    this.softwareSourceCanvases.set(display, canvas);
    return canvas;
  }

  private renderSoftwareDecodedFrame(
    display: number,
    rgba: Uint8Array,
    width: number,
    height: number,
    displayWidth: number,
    displayHeight: number
  ): void {
    const start = nowMs();
    try {
      if (width <= 0 || height <= 0) {
        return;
      }
      const targetWidth = Math.max(1, displayWidth || width);
      const targetHeight = Math.max(1, displayHeight || height);
      if (
        this.renderSoftwareToDirectSurface(
          display,
          rgba,
          width,
          height,
          targetWidth,
          targetHeight
        )
      ) {
        this.notifyFrame(display, targetWidth, targetHeight);
        return;
      }
      if (targetWidth === width && targetHeight === height) {
        this.sink(display, rgba, width, height);
        this.notifyFrame(display, width, height);
        return;
      }
      const sourceCanvas = this.ensureSoftwareSourceCanvas(display, width, height);
      const sourceCtx = getCanvasContext(sourceCanvas);
      if (!sourceCtx) {
        return;
      }
      writeRgbaToCanvas(sourceCtx, width, height, rgba);
      const targetCtx = this.ensureContext(display, targetWidth, targetHeight);
      if (!targetCtx) {
        return;
      }
      applySamplingPolicy(targetCtx, width, height, targetWidth, targetHeight);
      targetCtx.clearRect(0, 0, targetWidth, targetHeight);
      targetCtx.drawImage(sourceCanvas, 0, 0, targetWidth, targetHeight);
      const imageData = targetCtx.getImageData(0, 0, targetWidth, targetHeight);
      const scaled = new Uint8Array(
        imageData.data.buffer,
        imageData.data.byteOffset,
        imageData.data.byteLength
      );
      this.sink(display, scaled, targetWidth, targetHeight);
      this.notifyFrame(display, targetWidth, targetHeight);
    } catch (err) {
      this.logger.error('Software video decode failed', err);
    } finally {
      this.recordRenderCost(display, nowMs() - start);
    }
  }

  private renderSoftwareToDirectSurface(
    display: number,
    rgba: Uint8Array,
    width: number,
    height: number,
    displayWidth: number,
    displayHeight: number
  ): boolean {
    const ctx = this.ensureDirectSurfaceContext(displayWidth, displayHeight);
    if (!ctx || !this.directSurfaceCanvas) {
      return false;
    }
    const sourceCanvas = this.ensureSoftwareSourceCanvas(display, width, height);
    const sourceCtx = getCanvasContext(sourceCanvas);
    if (!sourceCtx) {
      return false;
    }
    writeRgbaToCanvas(sourceCtx, width, height, rgba);
    applySamplingPolicy(
      ctx,
      width,
      height,
      this.directSurfaceCanvas.width,
      this.directSurfaceCanvas.height
    );
    ctx.clearRect(0, 0, this.directSurfaceCanvas.width, this.directSurfaceCanvas.height);
    ctx.drawImage(
      sourceCanvas,
      0,
      0,
      this.directSurfaceCanvas.width,
      this.directSurfaceCanvas.height
    );
    return true;
  }

  private renderToDirectSurface(
    display: number,
    frame: VideoFrame,
    width: number,
    height: number
  ): boolean {
    this.directSurfaceActiveDisplay = display;
    if (this.directSurfaceUseWorker) {
      return true;
    }
    const ctx = this.ensureDirectSurfaceContext(width, height);
    if (!ctx || !this.directSurfaceCanvas) {
      return false;
    }
    const canvas = this.directSurfaceCanvas;
    applySamplingPolicy(ctx, width, height, canvas.width, canvas.height);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
    return true;
  }

  private ensureDirectSurfaceContext(
    sourceWidth: number,
    sourceHeight: number
  ): DirectCanvasContext | null {
    if (!this.directSurfaceElementId || typeof document === 'undefined') {
      return null;
    }
    if (
      !this.directSurfaceHost ||
      this.directSurfaceHost.id !== this.directSurfaceElementId ||
      !this.directSurfaceHost.isConnected
    ) {
      this.detachSurfaceFromWorker();
      const host = document.getElementById(this.directSurfaceElementId);
      if (!host) {
        return null;
      }
      this.directSurfaceHost = host;
      this.directSurfaceCanvas = null;
      this.directSurfaceContext = null;
      this.startDirectSurfaceObserver(host);
    }
    if (!this.directSurfaceHost) {
      return null;
    }
    this.directSurfaceSourceWidth = sourceWidth;
    this.directSurfaceSourceHeight = sourceHeight;
    if (!this.directSurfaceCanvas || !this.directSurfaceCanvas.isConnected) {
      const canvas = this.createDirectSurfaceCanvasElement();
      this.directSurfaceHost.textContent = '';
      this.directSurfaceHost.append(canvas);
      this.directSurfaceCanvas = canvas;
      this.directSurfaceContext = null;
      this.refreshDirectSurfaceSizing(true);
      if (this.tryAttachSurfaceToWorker(canvas)) {
        this.directSurfaceContext = null;
      }
    }
    if (!this.directSurfaceCanvas) {
      return null;
    }
    this.refreshDirectSurfaceSizing(false);
    if (this.directSurfaceUseWorker) {
      return null;
    }
    if (!this.directSurfaceContext) {
      const ctx = this.directSurfaceCanvas.getContext('2d', {
        alpha: false,
        desynchronized: true
      });
      if (!ctx || !isDirectCanvasContext(ctx)) {
        return null;
      }
      this.directSurfaceContext = ctx;
    }
    return this.directSurfaceContext;
  }

  private createDirectSurfaceCanvasElement(): HTMLCanvasElement {
    const canvas = document.createElement('canvas');
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.display = 'block';
    canvas.style.pointerEvents = 'none';
    return canvas;
  }

  private releaseDirectSurface(): void {
    if (this.directSurfaceResizeObserver) {
      this.directSurfaceResizeObserver.disconnect();
      this.directSurfaceResizeObserver = null;
    }
    this.cancelDirectSurfaceViewportSync();
    this.detachDirectSurfaceViewportListeners();
    this.clearDirectSurfaceRecoveryTimers();
    if (this.directSurfaceCanvas && this.directSurfaceCanvas.isConnected) {
      this.directSurfaceCanvas.remove();
    }
    this.detachSurfaceFromWorker();
    this.directSurfaceHost = null;
    this.directSurfaceCanvas = null;
    this.directSurfaceContext = null;
    this.directSurfaceCssWidth = 0;
    this.directSurfaceCssHeight = 0;
    this.directSurfaceNativeDpr = 1;
    this.directSurfaceDpr = 1;
    this.directSurfaceSourceWidth = 0;
    this.directSurfaceSourceHeight = 0;
    this.directSurfaceBackingWidth = 0;
    this.directSurfaceBackingHeight = 0;
    this.directSurfaceLastMeasureMs = 0;
    this.directSurfaceViewportChanged = false;
    this.directSurfaceUseWorker = false;
    this.adaptiveStartupUntil.clear();
    this.lastFrameRenderedAt.clear();
    this.notifiedFrameSize.clear();
  }

  private startDirectSurfaceObserver(host: HTMLElement): void {
    if (this.directSurfaceResizeObserver) {
      this.directSurfaceResizeObserver.disconnect();
      this.directSurfaceResizeObserver = null;
    }
    this.cancelDirectSurfaceViewportSync();
    this.detachDirectSurfaceViewportListeners();
    if (typeof ResizeObserver !== 'undefined') {
      this.directSurfaceResizeObserver = new ResizeObserver(() => {
        this.scheduleDirectSurfaceViewportResize();
      });
      this.directSurfaceResizeObserver.observe(host);
    }
    this.attachDirectSurfaceViewportListeners();
    this.measureDirectSurfaceHost(true);
  }

  private attachDirectSurfaceViewportListeners(): void {
    if (typeof window === 'undefined') {
      return;
    }
    this.directSurfaceWindowResizeListener = (() => {
      this.scheduleDirectSurfaceViewportResize();
    }) as EventListener;
    window.addEventListener('resize', this.directSurfaceWindowResizeListener);
    if (!window.visualViewport) {
      return;
    }
    this.directSurfaceViewportResizeListener = (() => {
      this.scheduleDirectSurfaceViewportResize();
    }) as EventListener;
    window.visualViewport.addEventListener(
      'resize',
      this.directSurfaceViewportResizeListener
    );
  }

  private detachDirectSurfaceViewportListeners(): void {
    if (typeof window === 'undefined') {
      this.directSurfaceWindowResizeListener = null;
      this.directSurfaceViewportResizeListener = null;
      return;
    }
    if (this.directSurfaceWindowResizeListener) {
      window.removeEventListener('resize', this.directSurfaceWindowResizeListener);
      this.directSurfaceWindowResizeListener = null;
    }
    if (this.directSurfaceViewportResizeListener && window.visualViewport) {
      window.visualViewport.removeEventListener(
        'resize',
        this.directSurfaceViewportResizeListener
      );
      this.directSurfaceViewportResizeListener = null;
    }
  }

  private handleDirectSurfaceViewportResize(): void {
    this.measureDirectSurfaceHost(true);
    this.refreshDirectSurfaceSizing(true);
  }

  private scheduleDirectSurfaceViewportResize(): void {
    if (this.directSurfaceViewportSyncHandle !== undefined) {
      return;
    }
    if (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function') {
      this.directSurfaceViewportSyncHandle = window.requestAnimationFrame(() => {
        this.directSurfaceViewportSyncHandle = undefined;
        this.handleDirectSurfaceViewportResize();
      });
      return;
    }
    this.directSurfaceViewportSyncHandle = window.setTimeout(() => {
      this.directSurfaceViewportSyncHandle = undefined;
      this.handleDirectSurfaceViewportResize();
    }, 16);
  }

  private cancelDirectSurfaceViewportSync(): void {
    if (this.directSurfaceViewportSyncHandle === undefined) {
      return;
    }
    if (typeof window !== 'undefined' && typeof window.cancelAnimationFrame === 'function') {
      window.cancelAnimationFrame(this.directSurfaceViewportSyncHandle);
    } else {
      window.clearTimeout(this.directSurfaceViewportSyncHandle);
    }
    this.directSurfaceViewportSyncHandle = undefined;
  }

  private refreshDirectSurfaceSizing(forceMeasure: boolean): void {
    if (!this.directSurfaceCanvas || !this.directSurfaceHost) {
      return;
    }
    this.measureDirectSurfaceHost(forceMeasure);
    const viewportChanged = this.directSurfaceViewportChanged;
    const hostWidth = Math.max(
      1,
      this.directSurfaceCssWidth || this.directSurfaceSourceWidth || 1
    );
    const hostHeight = Math.max(
      1,
      this.directSurfaceCssHeight || this.directSurfaceSourceHeight || 1
    );
    let targetWidth = Math.max(
      1,
      Math.round(hostWidth * this.directSurfaceDpr)
    );
    let targetHeight = Math.max(
      1,
      Math.round(hostHeight * this.directSurfaceDpr)
    );
    const maxPixels = this.getDirectSurfacePixelBudget();
    if (maxPixels > 0) {
      const fitted = fitSurfaceToPixelBudget(targetWidth, targetHeight, maxPixels);
      targetWidth = fitted.width;
      targetHeight = fitted.height;
    }
    const currentWidth = Math.max(
      1,
      this.directSurfaceBackingWidth || this.directSurfaceCanvas.width || 1
    );
    const currentHeight = Math.max(
      1,
      this.directSurfaceBackingHeight || this.directSurfaceCanvas.height || 1
    );
    const widthDelta = Math.abs(currentWidth - targetWidth);
    const heightDelta = Math.abs(currentHeight - targetHeight);
    if (widthDelta <= 1 && heightDelta <= 1) {
      this.directSurfaceViewportChanged = false;
      return;
    }
    const widthDriftRatio = widthDelta / Math.max(currentWidth, targetWidth);
    const heightDriftRatio = heightDelta / Math.max(currentHeight, targetHeight);
    // Avoid frequent tiny surface reallocations which can cause visible
    // sharpness pumping under fluctuating load.
    if (!viewportChanged && widthDriftRatio < 0.02 && heightDriftRatio < 0.02) {
      this.directSurfaceViewportChanged = false;
      return;
    }
    this.directSurfaceViewportChanged = false;
    this.applyDirectSurfaceSize(targetWidth, targetHeight);
    if (viewportChanged) {
      this.scheduleDirectSurfaceRecovery();
    }
  }

  private applyDirectSurfaceSize(width: number, height: number): void {
    if (!this.directSurfaceCanvas) {
      return;
    }
    if (
      this.directSurfaceBackingWidth === width &&
      this.directSurfaceBackingHeight === height
    ) {
      return;
    }
    this.directSurfaceBackingWidth = width;
    this.directSurfaceBackingHeight = height;
    if (this.directSurfaceUseWorker) {
      this.worker?.postMessage({
        type: 'resize_surface',
        width,
        height
      });
    } else {
      const snapshot = this.captureCanvasSnapshot(this.directSurfaceCanvas);
      this.directSurfaceCanvas.width = width;
      this.directSurfaceCanvas.height = height;
      const ctx =
        this.directSurfaceContext ??
        this.directSurfaceCanvas.getContext('2d', {
          alpha: false,
          desynchronized: true
        });
      if (ctx && isDirectCanvasContext(ctx)) {
        this.directSurfaceContext = ctx;
        this.restoreCanvasSnapshot(ctx, snapshot, width, height);
      }
    }
  }

  private captureCanvasSnapshot(
    source: HTMLCanvasElement
  ): OffscreenCanvas | HTMLCanvasElement | null {
    const width = Math.max(1, source.width || 0);
    const height = Math.max(1, source.height || 0);
    if (width <= 0 || height <= 0) {
      return null;
    }
    let snapshot: OffscreenCanvas | HTMLCanvasElement;
    if (typeof OffscreenCanvas !== 'undefined') {
      snapshot = new OffscreenCanvas(width, height);
    } else {
      const element = document.createElement('canvas');
      element.width = width;
      element.height = height;
      snapshot = element;
    }
    const ctx = getCanvasContext(snapshot);
    if (!ctx) {
      return null;
    }
    ctx.drawImage(source, 0, 0, width, height);
    return snapshot;
  }

  private restoreCanvasSnapshot(
    ctx: DirectCanvasContext,
    snapshot: OffscreenCanvas | HTMLCanvasElement | null,
    targetWidth: number,
    targetHeight: number
  ): void {
    if (!snapshot || targetWidth <= 0 || targetHeight <= 0) {
      return;
    }
    const sourceWidth = Math.max(1, snapshot.width || targetWidth);
    const sourceHeight = Math.max(1, snapshot.height || targetHeight);
    applySamplingPolicy(ctx, sourceWidth, sourceHeight, targetWidth, targetHeight);
    ctx.clearRect(0, 0, targetWidth, targetHeight);
    ctx.drawImage(snapshot, 0, 0, targetWidth, targetHeight);
  }

  private restoreCanvasSnapshotInto(
    canvas: HTMLCanvasElement,
    snapshot: OffscreenCanvas | HTMLCanvasElement | null
  ): void {
    if (!snapshot) {
      return;
    }
    const ctx = canvas.getContext('2d', {
      alpha: false,
      desynchronized: true
    });
    if (!ctx || !isDirectCanvasContext(ctx)) {
      return;
    }
    this.directSurfaceContext = ctx;
    this.restoreCanvasSnapshot(ctx, snapshot, canvas.width, canvas.height);
  }

  private measureDirectSurfaceHost(force: boolean): void {
    if (!this.directSurfaceHost) {
      return;
    }
    const now = Date.now();
    if (!force && now - this.directSurfaceLastMeasureMs < 250) {
      return;
    }
    this.directSurfaceLastMeasureMs = now;
    const previousCssWidth = this.directSurfaceCssWidth;
    const previousCssHeight = this.directSurfaceCssHeight;
    const previousNativeDpr = this.directSurfaceNativeDpr;
    const rect = this.directSurfaceHost.getBoundingClientRect();
    this.directSurfaceCssWidth = Math.max(
      1,
      Math.round(rect.width || this.directSurfaceSourceWidth || 1)
    );
    this.directSurfaceCssHeight = Math.max(
      1,
      Math.round(rect.height || this.directSurfaceSourceHeight || 1)
    );
    const nativeDpr =
      typeof window !== 'undefined' && Number.isFinite(window.devicePixelRatio)
        ? Math.max(window.devicePixelRatio, 1)
        : 1;
    this.directSurfaceNativeDpr = nativeDpr;
    if (
      previousCssWidth > 0 &&
      previousCssHeight > 0 &&
      (previousCssWidth !== this.directSurfaceCssWidth ||
        previousCssHeight !== this.directSurfaceCssHeight ||
        Math.abs(previousNativeDpr - nativeDpr) > 0.01)
    ) {
      this.directSurfaceViewportChanged = true;
    }
    const logicalSize = this.getDirectSurfaceLogicalSize();
    const sourcePixels = logicalSize.width * logicalSize.height;
    const profile = this.getActiveRenderProfile();
    const adaptive = this.getAdaptiveRenderState(this.directSurfaceActiveDisplay);
    let dprCap = profile.dprCapDefault;
    if (sourcePixels >= 2560 * 1440) {
      dprCap = Math.min(dprCap, profile.dprCapQhd);
    } else if (sourcePixels >= 1920 * 1080) {
      dprCap = Math.min(dprCap, profile.dprCapFullHd);
    }
    // Use smoothed stress signal instead of instant render timing to reduce
    // quality oscillation (blur-clear flicker) under borderline load.
    if (adaptive.stressEma >= 1.05) {
      dprCap = Math.min(dprCap, profile.dprCapHeavyLoad);
    } else if (adaptive.stressEma >= 0.65) {
      dprCap = Math.min(dprCap, profile.dprCapMediumLoad);
    }
    dprCap *= adaptive.dprScale;
    const sourceFitDpr =
      logicalSize.width > 0 &&
      logicalSize.height > 0 &&
      this.directSurfaceCssWidth > 0 &&
      this.directSurfaceCssHeight > 0
        ? Math.min(
            logicalSize.width / this.directSurfaceCssWidth,
            logicalSize.height / this.directSurfaceCssHeight
          )
        : 1;
    let dprFloor = 0.75;
    if (this.renderQualityPreference === 'balanced') {
      if (adaptive.stressEma < 1.15) {
        dprFloor = Math.min(nativeDpr, Math.max(0.84, sourceFitDpr * 0.96));
      } else {
        dprFloor = 0.8;
      }
    } else if (
      this.renderQualityPreference === 'best' ||
      this.renderQualityPreference === 'custom'
    ) {
      if (adaptive.stressEma < 1.2) {
        dprFloor = Math.min(nativeDpr, Math.max(0.9, sourceFitDpr));
      } else {
        dprFloor = Math.min(nativeDpr, Math.max(0.82, sourceFitDpr * 0.9));
      }
    }
    this.directSurfaceDpr = Math.min(nativeDpr, Math.max(dprFloor, dprCap));
  }

  private scheduleDirectSurfaceRecovery(): void {
    const activeDisplay = this.activeDisplay;
    if (
      activeDisplay === null ||
      !this.onNeedRefresh ||
      this.directSurfaceSourceWidth <= 0 ||
      this.directSurfaceSourceHeight <= 0
    ) {
      return;
    }
    const baselineFrameAt = this.lastFrameRenderedAt.get(activeDisplay) ?? 0;
    this.clearDirectSurfaceRecoveryTimers();
    this.directSurfaceRecoveryTimer = window.setTimeout(() => {
      this.directSurfaceRecoveryTimer = undefined;
      const currentDisplay = this.activeDisplay;
      if (currentDisplay === null) {
        return;
      }
      this.directSurfaceRecoveryDisplay = currentDisplay;
      this.directSurfaceRecoveryRequestedAt = Date.now();
      this.onNeedRefresh?.(currentDisplay);
      this.directSurfaceHardRecoveryTimer = window.setTimeout(() => {
        this.directSurfaceHardRecoveryTimer = undefined;
        const latestDisplay = this.activeDisplay;
        if (latestDisplay === null || latestDisplay !== currentDisplay) {
          this.directSurfaceRecoveryDisplay = null;
          return;
        }
        const latestFrameAt = this.lastFrameRenderedAt.get(currentDisplay) ?? 0;
        if (
          latestFrameAt > baselineFrameAt &&
          latestFrameAt >= this.directSurfaceRecoveryRequestedAt
        ) {
          this.directSurfaceRecoveryDisplay = null;
          this.directSurfaceRecoveryRequestedAt = 0;
          return;
        }
        this.resetDisplayState(currentDisplay);
        this.syncWorkerActiveDisplay(true);
        this.onNeedRefresh?.(currentDisplay);
        this.directSurfaceRecoveryDisplay = null;
        this.directSurfaceRecoveryRequestedAt = 0;
      }, 180);
    }, 60);
  }

  private clearDirectSurfaceRecoveryTimers(): void {
    if (this.directSurfaceRecoveryTimer !== undefined) {
      window.clearTimeout(this.directSurfaceRecoveryTimer);
      this.directSurfaceRecoveryTimer = undefined;
    }
    if (this.directSurfaceHardRecoveryTimer !== undefined) {
      window.clearTimeout(this.directSurfaceHardRecoveryTimer);
      this.directSurfaceHardRecoveryTimer = undefined;
    }
    this.directSurfaceRecoveryDisplay = null;
    this.directSurfaceRecoveryRequestedAt = 0;
  }

  private maybeCompleteDirectSurfaceRecovery(display: number): void {
    if (
      this.directSurfaceRecoveryDisplay !== display ||
      this.directSurfaceHardRecoveryTimer === undefined
    ) {
      return;
    }
    if (Date.now() < this.directSurfaceRecoveryRequestedAt) {
      return;
    }
    window.clearTimeout(this.directSurfaceHardRecoveryTimer);
    this.directSurfaceHardRecoveryTimer = undefined;
    this.directSurfaceRecoveryDisplay = null;
    this.directSurfaceRecoveryRequestedAt = 0;
  }

  private getDirectSurfaceLogicalSize(): DisplayGeometry {
    const display =
      this.activeDisplay !== null ? this.activeDisplay : this.directSurfaceActiveDisplay;
    const geometry = this.displayGeometries.get(display);
    if (geometry && geometry.width > 0 && geometry.height > 0) {
      return geometry;
    }
    return {
      width: Math.max(1, this.directSurfaceSourceWidth || 1),
      height: Math.max(1, this.directSurfaceSourceHeight || 1)
    };
  }

  private getActiveRenderProfile(): RenderQualityProfile {
    if (this.renderQualityPreference !== 'custom') {
      return RENDER_QUALITY_PROFILES[this.renderQualityPreference];
    }
    const best = RENDER_QUALITY_PROFILES.best;
    // Keep custom mode slightly above "best" by default.
    const qualityScale = this.getCustomQualityScale() * 1.05;
    const budgetScale = qualityScale * qualityScale;
    return {
      dprCapDefault: clamp(
        best.dprCapDefault * qualityScale,
        1.0,
        2.8
      ),
      dprCapFullHd: clamp(
        best.dprCapFullHd * qualityScale,
        0.95,
        2.35
      ),
      dprCapQhd: clamp(
        best.dprCapQhd * qualityScale,
        0.85,
        1.95
      ),
      dprCapMediumLoad: clamp(
        best.dprCapMediumLoad * qualityScale,
        0.82,
        1.85
      ),
      dprCapHeavyLoad: clamp(
        best.dprCapHeavyLoad * qualityScale,
        0.78,
        1.45
      ),
      pixelBudgetDefault: Math.round(
        clamp(
          best.pixelBudgetDefault * budgetScale,
          1280 * 720,
          3840 * 2160
        )
      ),
      pixelBudgetQhd: Math.round(
        clamp(
          best.pixelBudgetQhd * budgetScale,
          1280 * 720,
          3840 * 2160
        )
      )
    };
  }

  private getAdaptiveBounds(): AdaptiveRenderScaleBounds {
    if (this.renderQualityPreference !== 'custom') {
      return ADAPTIVE_RENDER_SCALE_BOUNDS[this.renderQualityPreference];
    }
    const customScale = this.getCustomQualityScale() * 1.05;
    return {
      minBudgetScale: clamp(0.99 + (customScale - 1) * 0.08, 0.92, 1.15),
      maxBudgetScale: clamp(1.7 + (customScale - 1) * 0.5, 1.4, 2.2),
      minDprScale: clamp(1.0 + (customScale - 1) * 0.05, 0.94, 1.15),
      maxDprScale: clamp(1.3 + (customScale - 1) * 0.24, 1.12, 1.58)
    };
  }

  private getCustomQualityScale(): number {
    const qualityRatio = Math.max(this.customImageQuality, 10) / 100;
    const qualityScale = Math.pow(qualityRatio, 0.35);
    const fpsScale = Math.pow(60 / Math.max(this.customFps, 5), 0.2);
    return clamp(qualityScale * fpsScale, 0.72, 1.6);
  }

  private getDirectSurfacePixelBudget(): number {
    const sourcePixels = this.directSurfaceSourceWidth * this.directSurfaceSourceHeight;
    const profile = this.getActiveRenderProfile();
    const adaptive = this.getAdaptiveRenderState(this.directSurfaceActiveDisplay);
    let budget = profile.pixelBudgetDefault;
    if (sourcePixels >= 2560 * 1440) {
      budget = profile.pixelBudgetQhd;
    }
    if (sourcePixels > 0) {
      if (this.renderQualityPreference === 'balanced') {
        budget = Math.max(budget, Math.floor(sourcePixels * 0.98));
      } else if (
        this.renderQualityPreference === 'best' ||
        this.renderQualityPreference === 'custom'
      ) {
        budget = Math.max(budget, sourcePixels);
      }
    }
    budget = Math.max(640 * 360, Math.floor(budget * adaptive.budgetScale));
    const perf = this.displayPerf.get(this.directSurfaceActiveDisplay);
    if (!perf) {
      return budget;
    }
    let mediumFactor = 0.72;
    let heavyFactor = 0.55;
    let heavyStressThreshold = 1.1;
    let mediumStressThreshold = 0.7;
    let hardSlowThreshold = 8;
    let heavyRenderMsThreshold = 28;
    if (this.renderQualityPreference === 'balanced') {
      mediumFactor = 0.84;
      heavyFactor = 0.72;
      heavyStressThreshold = 1.28;
      mediumStressThreshold = 0.92;
      hardSlowThreshold = 10;
      heavyRenderMsThreshold = 31;
    } else if (
      this.renderQualityPreference === 'best' ||
      this.renderQualityPreference === 'custom'
    ) {
      mediumFactor = 0.9;
      heavyFactor = 0.78;
      heavyStressThreshold = 1.38;
      mediumStressThreshold = 1.0;
      hardSlowThreshold = 10;
      heavyRenderMsThreshold = 34;
    } else if (this.renderQualityPreference === 'low') {
      mediumFactor = 0.66;
      heavyFactor = 0.48;
      heavyStressThreshold = 1.08;
      mediumStressThreshold = 0.65;
      hardSlowThreshold = 7;
      heavyRenderMsThreshold = 26;
    }
    const loadBaseBudget = Math.max(profile.pixelBudgetDefault, budget);
    let mediumLoadBudget = Math.max(
      960 * 540,
      Math.floor(loadBaseBudget * mediumFactor)
    );
    let heavyLoadBudget = Math.max(
      640 * 360,
      Math.floor(loadBaseBudget * heavyFactor)
    );
    if (
      sourcePixels > 0 &&
      this.renderQualityPreference !== 'low'
    ) {
      mediumLoadBudget = Math.max(mediumLoadBudget, Math.floor(sourcePixels * 0.88));
      heavyLoadBudget = Math.max(heavyLoadBudget, Math.floor(sourcePixels * 0.78));
    }
    if (
      perf.consecutiveSlowRenders >= hardSlowThreshold ||
      perf.avgRenderMs >= heavyRenderMsThreshold
    ) {
      return Math.min(budget, heavyLoadBudget);
    }
    if (adaptive.stressEma >= heavyStressThreshold) {
      return Math.min(budget, heavyLoadBudget);
    }
    if (adaptive.stressEma >= mediumStressThreshold) {
      return Math.min(budget, mediumLoadBudget);
    }
    return budget;
  }

  private decoderKey(display: number, codec: CodecType): string {
    return `${display}:${codec}`;
  }

  private isSoftwareBackedCodec(codec: CodecType): boolean {
    return codec === 'vp8' || codec === 'vp9' || codec === 'av1';
  }

  private sendDecodeToWorker(input: DecodeInput): boolean {
    if (this.isSoftwareBackedCodec(input.codec)) {
      return false;
    }
    if (
      !this.directSurfaceUseWorker ||
      !this.worker ||
      !this.workerReady ||
      !this.workerSurfaceAttached
    ) {
      return false;
    }
    const payload = this.toTransferablePayload(input.data);
    this.worker.postMessage(
      {
        type: 'decode',
        codec: input.codec,
        display: input.display,
        key: input.key,
        pts:
          typeof input.pts === 'string'
            ? Number(input.pts)
            : Number.isFinite(input.pts)
            ? Number(input.pts)
            : 0,
        data: payload
      },
      [payload.buffer]
    );
    return true;
  }

  private toTransferablePayload(data: Uint8Array): Uint8Array {
    if (data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) {
      return data;
    }
    return data.slice();
  }

  private ensureWorker(): void {
    if (
      !this.workerSupported ||
      this.workerUnavailable ||
      this.worker !== null
    ) {
      return;
    }
    this.workerFallbackTried = false;
    this.startWorker('module');
  }

  private startWorker(mode: WorkerMode): void {
    try {
      const worker =
        mode === 'module'
          ? new Worker(new URL('./video_worker.ts', import.meta.url), { type: 'module' })
          : new Worker(new URL('./video_worker.ts', import.meta.url));
      this.worker = worker;
      this.workerMode = mode;
      this.workerReady = false;
      this.workerSurfaceAttached = false;
      this.logger.info(`Starting video worker (${mode})`);
      this.armWorkerInitTimeout(mode);
      worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
        this.handleWorkerMessage(event.data);
      };
      worker.onmessageerror = () => {
        this.logger.warn(`Video worker messageerror (${mode})`);
      };
      worker.onerror = (event: ErrorEvent) => {
        const detail =
          event.message ||
          `${event.filename || 'worker'}:${event.lineno || 0}:${event.colno || 0}`;
        this.logger.warn(`Video worker failed (${mode}): ${detail}`);
        if (this.worker !== worker) {
          return;
        }
        this.clearWorkerInitTimeout();
        if (mode === 'module' && !this.workerFallbackTried) {
          this.workerFallbackTried = true;
          this.shutdownWorker();
          this.startWorker('classic');
          return;
        }
        this.workerUnavailable = true;
        this.shutdownWorker();
      };
    } catch (err) {
      this.logger.warn(`Video worker startup threw (${mode})`, err);
      if (mode === 'module' && !this.workerFallbackTried) {
        this.workerFallbackTried = true;
        this.shutdownWorker();
        this.startWorker('classic');
        return;
      }
      this.workerUnavailable = true;
      this.shutdownWorker();
    }
  }

  private armWorkerInitTimeout(mode: WorkerMode): void {
    this.clearWorkerInitTimeout();
    this.workerInitTimer = window.setTimeout(() => {
      if (!this.worker || this.workerReady) {
        return;
      }
      this.logger.warn(`Video worker startup timed out (${mode})`);
      if (mode === 'module' && !this.workerFallbackTried) {
        this.workerFallbackTried = true;
        this.shutdownWorker();
        this.startWorker('classic');
        return;
      }
      this.workerUnavailable = true;
      this.shutdownWorker();
    }, 2500);
  }

  private clearWorkerInitTimeout(): void {
    if (this.workerInitTimer !== undefined) {
      window.clearTimeout(this.workerInitTimer);
      this.workerInitTimer = undefined;
    }
  }

  private tryAttachSurfaceToWorker(canvas: HTMLCanvasElement): boolean {
    if (!this.workerSupported || this.workerUnavailable) {
      return false;
    }
    // transferControlToOffscreen() must run before any 2D/WebGL context exists.
    if (this.directSurfaceContext) {
      return false;
    }
    this.ensureWorker();
    if (!this.worker || !this.workerReady || this.workerSurfaceAttached) {
      return this.workerSurfaceAttached;
    }
    if (typeof canvas.transferControlToOffscreen !== 'function') {
      return false;
    }
    try {
      const offscreen = canvas.transferControlToOffscreen();
      this.worker.postMessage(
        {
          type: 'attach_surface',
          canvas: offscreen,
          width: Math.max(1, canvas.width || 1),
          height: Math.max(1, canvas.height || 1)
        },
        [offscreen]
      );
      this.syncWorkerRenderPolicy();
      this.workerSurfaceAttached = true;
      this.directSurfaceUseWorker = true;
      this.directSurfaceContext = null;
      return true;
    } catch (err) {
      this.logger.warn('Failed to attach worker surface, fallback to main thread', err);
      this.workerUnavailable = true;
      this.shutdownWorker();
      return false;
    }
  }

  private tryUpgradeDirectSurfaceToWorker(): void {
    if (!this.worker || !this.workerReady || this.workerSurfaceAttached) {
      return;
    }
    if (!this.directSurfaceCanvas) {
      return;
    }
    let targetCanvas = this.directSurfaceCanvas;
    if (this.directSurfaceContext) {
      const replaced = this.replaceDirectSurfaceCanvas();
      if (!replaced) {
        return;
      }
      targetCanvas = replaced;
    }
    this.tryAttachSurfaceToWorker(targetCanvas);
  }

  private replaceDirectSurfaceCanvas(): HTMLCanvasElement | null {
    if (!this.directSurfaceHost || !this.directSurfaceCanvas) {
      return null;
    }
    const previous = this.directSurfaceCanvas;
    const snapshot = this.captureCanvasSnapshot(previous);
    const canvas = this.createDirectSurfaceCanvasElement();
    canvas.width = Math.max(
      1,
      this.directSurfaceBackingWidth || previous.width || 1
    );
    canvas.height = Math.max(
      1,
      this.directSurfaceBackingHeight || previous.height || 1
    );
    try {
      if (previous.parentElement === this.directSurfaceHost) {
        this.directSurfaceHost.replaceChild(canvas, previous);
      } else {
        this.directSurfaceHost.textContent = '';
        this.directSurfaceHost.append(canvas);
      }
    } catch (err) {
      this.logger.warn('Failed to replace direct surface canvas for worker attach', err);
      return null;
    }
    this.directSurfaceCanvas = canvas;
    this.directSurfaceContext = null;
    this.restoreCanvasSnapshotInto(canvas, snapshot);
    this.directSurfaceLastMeasureMs = 0;
    this.refreshDirectSurfaceSizing(true);
    return canvas;
  }

  private restoreDirectSurfaceCanvasFromWorker(): void {
    const replaced = this.replaceDirectSurfaceCanvas();
    if (!replaced) {
      this.directSurfaceContext = null;
      return;
    }
    this.directSurfaceCanvas = replaced;
    this.directSurfaceContext = null;
  }

  private detachSurfaceFromWorker(restoreCanvas = false): void {
    const usedWorkerSurface = this.directSurfaceUseWorker || this.workerSurfaceAttached;
    if (this.worker && this.workerSurfaceAttached) {
      this.worker.postMessage({ type: 'detach_surface' });
    }
    this.workerSurfaceAttached = false;
    this.directSurfaceUseWorker = false;
    if (restoreCanvas && usedWorkerSurface) {
      this.restoreDirectSurfaceCanvasFromWorker();
    }
  }

  private handleWorkerMessage(message: WorkerMessage): void {
    if (!message || typeof message !== 'object') {
      return;
    }
    if (message.type === 'ready') {
      this.clearWorkerInitTimeout();
      if (!message.canDecode) {
        this.logger.warn(
          `Video worker unavailable in this browser context${
            message.reason ? `: ${message.reason}` : ''
          } (${this.workerMode ?? 'unknown'})`
        );
        this.workerUnavailable = true;
        this.shutdownWorker();
        return;
      }
      this.workerReady = true;
      this.workerDecodeFailureWindowStart = 0;
      this.workerDecodeFailureCount = 0;
      this.logger.info(`Video worker ready (${this.workerMode ?? 'unknown'})`);
      this.syncWorkerRenderPolicy();
      this.syncWorkerActiveDisplay(false);
      this.tryUpgradeDirectSurfaceToWorker();
      return;
    }
    if (message.type === 'frame') {
      if (!this.isActiveDisplay(message.display)) {
        return;
      }
      this.directSurfaceSourceWidth = Math.max(1, Math.floor(message.width || 0));
      this.directSurfaceSourceHeight = Math.max(1, Math.floor(message.height || 0));
      this.mergeWorkerFramePerf(message);
      this.refreshDirectSurfaceSizing(true);
      this.notifyFrame(message.display, message.width, message.height);
      return;
    }
    if (message.type === 'need_refresh') {
      if (this.onNeedRefresh && this.isActiveDisplay(message.display)) {
        const display = Number(message.display);
        this.onNeedRefresh(
          Number.isFinite(display) && display >= 0 ? Math.floor(display) : 0
        );
      }
      return;
    }
    if (message.type === 'log') {
      if (
        message.message.startsWith('Worker decode failed') ||
        message.message.startsWith('Worker decoder error')
      ) {
        this.trackWorkerDecodeFailure();
      }
      if (message.level === 'error') {
        this.logger.error(message.message);
      } else {
        this.logger.warn(message.message);
      }
    }
  }

  private shutdownWorker(): void {
    this.clearWorkerInitTimeout();
    this.detachSurfaceFromWorker(true);
    if (this.worker) {
      try {
        this.worker.postMessage({ type: 'close' });
      } catch {
        // ignore
      }
      this.worker.terminate();
    }
    this.worker = null;
    this.workerMode = null;
    this.workerReady = false;
    this.workerSurfaceAttached = false;
    this.directSurfaceUseWorker = false;
    this.workerDecodeFailureWindowStart = 0;
    this.workerDecodeFailureCount = 0;
  }

  private clearDisplayCodecState(display: number, keepCodec?: CodecType): void {
    const keepKey = keepCodec ? this.decoderKey(display, keepCodec) : '';
    const prefix = `${display}:`;
    for (const [key, decoder] of this.decoders.entries()) {
      if (!key.startsWith(prefix) || key === keepKey) {
        continue;
      }
      try {
        decoder.close();
      } catch {
        // ignore
      }
      this.decoders.delete(key);
      this.decoderBooting.delete(key);
      this.pendingDecodeInputs.delete(key);
      this.decoderNeedsKeyFrame.delete(key);
      this.decoderLastPts.delete(key);
      this.decoderBackpressureOverflowState.delete(key);
      this.needRefreshLastSentAt.delete(key);
    }
    for (const [key, decoder] of this.softwareDecoders.entries()) {
      if (!key.startsWith(prefix) || key === keepKey) {
        continue;
      }
      void decoder.then((item) => item.close());
      this.softwareDecoders.delete(key);
      this.decoderNeedsKeyFrame.delete(key);
      this.decoderLastPts.delete(key);
      this.needRefreshLastSentAt.delete(key);
    }
    for (const key of [...this.decoderBooting.keys()]) {
      if (key.startsWith(prefix) && key !== keepKey) {
        this.decoderBooting.delete(key);
      }
    }
    for (const key of [...this.pendingDecodeInputs.keys()]) {
      if (key.startsWith(prefix) && key !== keepKey) {
        this.pendingDecodeInputs.delete(key);
      }
    }
    for (const key of [...this.decoderNeedsKeyFrame.keys()]) {
      if (key.startsWith(prefix) && key !== keepKey) {
        this.decoderNeedsKeyFrame.delete(key);
      }
    }
    for (const key of [...this.decoderLastPts.keys()]) {
      if (key.startsWith(prefix) && key !== keepKey) {
        this.decoderLastPts.delete(key);
      }
    }
    for (const key of [...this.decoderBackpressureOverflowState.keys()]) {
      if (key.startsWith(prefix) && key !== keepKey) {
        this.decoderBackpressureOverflowState.delete(key);
      }
    }
    for (const key of [...this.needRefreshLastSentAt.keys()]) {
      if (key.startsWith(prefix) && key !== keepKey) {
        this.needRefreshLastSentAt.delete(key);
      }
    }
  }

  private enqueuePendingDecodeInput(key: string, input: DecodeInput): void {
    const queue = this.pendingDecodeInputs.get(key) ?? [];
    if (input.key) {
      queue.length = 0;
      queue.push(input);
      this.pendingDecodeInputs.set(key, queue);
      return;
    }
    if (queue.length >= 8) {
      queue.shift();
    }
    queue.push(input);
    this.pendingDecodeInputs.set(key, queue);
  }

  private decodeWithDecoder(decoder: VideoDecoder, input: DecodeInput): void {
    const key = this.decoderKey(input.display, input.codec);
    if (this.shouldWaitForKeyframe(key, input.display, input.key)) {
      return;
    }
    if (this.shouldDropForBackpressure(decoder, input, key)) {
      this.markDisplayBackpressureDrop(input.display);
      return;
    }
    const timestamp = this.normalizeTimestamp(key, input.pts);
    const chunk = new EncodedVideoChunk({
      type: input.key ? 'key' : 'delta',
      timestamp,
      data: input.data
    });
    try {
      decoder.decode(chunk);
    } catch (err) {
      this.decoderNeedsKeyFrame.set(key, true);
      this.needRefreshLastSentAt.delete(key);
      this.requestRefresh(input.display, key);
      this.logDecodeError(err);
    }
  }

  private shouldWaitForKeyframe(
    decoderKey: string,
    display: number,
    isKeyFrame: boolean
  ): boolean {
    const needsKey = this.decoderNeedsKeyFrame.get(decoderKey) !== false;
    if (!needsKey) {
      return false;
    }
    if (!isKeyFrame) {
      this.requestRefresh(display, decoderKey);
      return true;
    }
    this.decoderNeedsKeyFrame.set(decoderKey, false);
    this.decoderBackpressureOverflowState.delete(decoderKey);
    this.needRefreshLastSentAt.delete(decoderKey);
    return false;
  }

  private normalizeTimestamp(decoderKey: string, pts?: number | string): number {
    const raw =
      typeof pts === 'string' ? Number(pts) : Number.isFinite(pts) ? Number(pts) : 0;
    const last = this.decoderLastPts.get(decoderKey);
    let next = Number.isFinite(raw) ? Math.floor(raw) : 0;
    if (!Number.isFinite(next) || next < 0) {
      next = last !== undefined ? last + 1 : 0;
    }
    if (last !== undefined && next <= last) {
      next = last + 1;
    }
    this.decoderLastPts.set(decoderKey, next);
    return next;
  }

  private shouldDropForBackpressure(
    decoder: VideoDecoder,
    input: DecodeInput,
    decoderKey: string
  ): boolean {
    if (input.key) {
      this.decoderBackpressureOverflowState.delete(decoderKey);
      return false;
    }
    const queueSize = decoder.decodeQueueSize;
    const dropThreshold = this.getDecodeQueueDropThreshold();
    if (queueSize <= dropThreshold) {
      this.coolDownBackpressureState(decoderKey);
      return false;
    }
    const now = Date.now();
    const prev = this.decoderBackpressureOverflowState.get(decoderKey);
    const overflowCount =
      prev && now - prev.at < BACKPRESSURE_OVERFLOW_WINDOW_MS ? prev.count + 1 : 1;
    this.decoderBackpressureOverflowState.set(decoderKey, {
      count: overflowCount,
      at: now
    });
    if (overflowCount < BACKPRESSURE_KEYFRAME_TRIGGER_OVERFLOWS) {
      return true;
    }
    this.decoderBackpressureOverflowState.delete(decoderKey);
    this.decoderNeedsKeyFrame.set(decoderKey, true);
    this.needRefreshLastSentAt.delete(decoderKey);
    this.requestRefresh(input.display, decoderKey);
    if (now - this.lastQueueOverflowLogMs > 1500) {
      this.lastQueueOverflowLogMs = now;
      this.logger.warn(
        `Decoder queue overflow (${queueSize}>${dropThreshold}), waiting keyframe for display ${input.display}`
      );
    }
    return true;
  }

  private coolDownBackpressureState(decoderKey: string): void {
    const state = this.decoderBackpressureOverflowState.get(decoderKey);
    if (!state) {
      return;
    }
    if (state.count <= 1) {
      this.decoderBackpressureOverflowState.delete(decoderKey);
      return;
    }
    this.decoderBackpressureOverflowState.set(decoderKey, {
      count: state.count - 1,
      at: Date.now()
    });
  }

  private getDecodeQueueDropThreshold(): number {
    switch (this.renderQualityPreference) {
      case 'low':
        return 13;
      case 'best':
        return 20;
      case 'custom': {
        const qualityAdj = clamp(
          Math.round((this.customImageQuality - 100) / 100),
          -3,
          6
        );
        const fpsAdj = clamp(Math.round((60 - this.customFps) / 30), -2, 2);
        return Math.round(clamp(22 + qualityAdj + fpsAdj, 15, 30));
      }
      default:
        return 16;
    }
  }

  private getDisplayPerf(display: number): DisplayPerf {
    const existing = this.displayPerf.get(display);
    if (existing) {
      return existing;
    }
    const created: DisplayPerf = {
      avgRenderMs: 0,
      consecutiveSlowRenders: 0,
      droppedBackpressure: 0,
      droppedStale: 0
    };
    this.displayPerf.set(display, created);
    return created;
  }

  private markDisplayBackpressureDrop(display: number): void {
    const perf = this.getDisplayPerf(display);
    perf.droppedBackpressure += 1;
    this.maybeAdjustAdaptiveRenderScale(display);
  }

  private markDisplayStaleDrop(display: number): void {
    const perf = this.getDisplayPerf(display);
    perf.droppedStale += 1;
    this.maybeAdjustAdaptiveRenderScale(display);
  }

  private recordRenderCost(display: number, renderMs: number): void {
    const perf = this.getDisplayPerf(display);
    if (!Number.isFinite(renderMs) || renderMs < 0) {
      return;
    }
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
    this.maybeAdjustAdaptiveRenderScale(display);
  }

  private mergeWorkerFramePerf(message: WorkerFrameMessage): void {
    const perf = this.getDisplayPerf(message.display);
    const avgRenderMs = Number(message.avgRenderMs);
    if (Number.isFinite(avgRenderMs) && avgRenderMs >= 0) {
      perf.avgRenderMs =
        perf.avgRenderMs === 0 ? avgRenderMs : perf.avgRenderMs * 0.5 + avgRenderMs * 0.5;
    }
    const consecutiveSlowRenders = Number(message.consecutiveSlowRenders);
    if (
      Number.isFinite(consecutiveSlowRenders) &&
      consecutiveSlowRenders >= 0
    ) {
      perf.consecutiveSlowRenders = Math.floor(consecutiveSlowRenders);
    }
    const droppedBackpressure = Number(message.droppedBackpressure);
    if (Number.isFinite(droppedBackpressure) && droppedBackpressure >= 0) {
      perf.droppedBackpressure = Math.max(
        perf.droppedBackpressure,
        Math.floor(droppedBackpressure)
      );
    }
    const droppedStale = Number(message.droppedStale);
    if (Number.isFinite(droppedStale) && droppedStale >= 0) {
      perf.droppedStale = Math.max(perf.droppedStale, Math.floor(droppedStale));
    }
    this.maybeAdjustAdaptiveRenderScale(message.display);
  }

  private getAdaptiveRenderState(display: number): AdaptiveRenderState {
    const existing = this.adaptiveRenderState.get(display);
    if (existing) {
      return existing;
    }
    const perf = this.displayPerf.get(display);
    const created: AdaptiveRenderState = {
      budgetScale: 1,
      dprScale: 1,
      lastAdjustMs: 0,
      lastEvalMs: 0,
      lastBackpressureDrops: perf?.droppedBackpressure ?? 0,
      lastStaleDrops: perf?.droppedStale ?? 0,
      stressEma: 0,
      badWindows: 0,
      goodWindows: 0,
      pendingDownscaleConfirmations: 0
    };
    this.adaptiveRenderState.set(display, created);
    return created;
  }

  private maybeAdjustAdaptiveRenderScale(display: number): void {
    const perf = this.displayPerf.get(display);
    if (!perf) {
      return;
    }
    const state = this.getAdaptiveRenderState(display);
    const now = Date.now();
    const startupUntil = this.adaptiveStartupUntil.get(display) ?? 0;
    if (startupUntil > now) {
      state.lastEvalMs = now;
      state.lastBackpressureDrops = perf.droppedBackpressure;
      state.lastStaleDrops = perf.droppedStale;
      state.badWindows = 0;
      state.goodWindows = 0;
      state.pendingDownscaleConfirmations = 0;
      return;
    }
    if (
      state.lastEvalMs > 0 &&
      now - state.lastEvalMs < ADAPTIVE_EVAL_MIN_INTERVAL_MS
    ) {
      return;
    }
    const evalElapsedMs =
      state.lastEvalMs > 0 ? now - state.lastEvalMs : 1000;
    state.lastEvalMs = now;
    const dtSec = Math.max(evalElapsedMs / 1000, 0.2);
    const newBackpressureDrops = Math.max(
      0,
      perf.droppedBackpressure - state.lastBackpressureDrops
    );
    const newStaleDrops = Math.max(0, perf.droppedStale - state.lastStaleDrops);
    const stalePerSec = newStaleDrops / dtSec;

    const quality = this.renderQualityPreference;
    const isLow = quality === 'low';
    const isHigh = quality === 'best' || quality === 'custom';
    const avgHeavyMs = isLow ? 26 : isHigh ? 32 : 29;
    const avgMediumMs = isLow ? 21 : isHigh ? 26 : 24;
    const avgLightMs = isLow ? 17 : isHigh ? 22 : 20;
    const avgGoodMs = isHigh ? 12 : 11;
    const slowHardThreshold = isLow ? 6 : isHigh ? 9 : 8;
    const slowMediumThreshold = isLow ? 3 : isHigh ? 5 : 4;
    const slowLightThreshold = isLow ? 1 : isHigh ? 2 : 2;
    const dropWeight = isLow ? 0.35 : isHigh ? 0.25 : 0.3;
    const staleWeight = isLow ? 0.045 : isHigh ? 0.03 : 0.038;
    const hardBadBackpressure = isLow ? 2 : 3;
    const hardBadAvgMs = isLow ? 24 : isHigh ? 30 : 27;
    const stressBadThreshold = isLow ? 0.95 : isHigh ? 1.2 : 1.05;
    const stressGoodThreshold = isLow ? 0.3 : isHigh ? 0.26 : 0.28;
    const staleGoodThreshold = isLow ? 1.2 : isHigh ? 1.0 : 1.05;
    const badWindowsTrigger = isLow ? 2 : 3;
    const goodWindowsTrigger = isLow ? 6 : isHigh ? 8 : 7;
    const budgetDownHard = isLow ? 0.12 : isHigh ? 0.07 : 0.09;
    const budgetDownSoft = isLow ? 0.08 : isHigh ? 0.05 : 0.07;
    const dprDownHard = isLow ? 0.1 : isHigh ? 0.06 : 0.08;
    const dprDownSoft = isLow ? 0.07 : isHigh ? 0.04 : 0.06;
    const budgetUp = isLow ? 0.05 : isHigh ? 0.03 : 0.04;
    const dprUp = isLow ? 0.04 : isHigh ? 0.02 : 0.03;
    const budgetRecovery = isLow ? 0.03 : isHigh ? 0.02 : 0.025;
    const dprRecovery = isLow ? 0.02 : isHigh ? 0.015 : 0.018;

    let stressScore = 0;
    if (perf.avgRenderMs >= avgHeavyMs) {
      stressScore += 0.95;
    } else if (perf.avgRenderMs >= avgMediumMs) {
      stressScore += 0.6;
    } else if (perf.avgRenderMs >= avgLightMs) {
      stressScore += 0.35;
    } else if (perf.avgRenderMs > 0 && perf.avgRenderMs <= avgGoodMs) {
      stressScore -= 0.08;
    }
    if (perf.consecutiveSlowRenders >= slowHardThreshold) {
      stressScore += 0.65;
    } else if (perf.consecutiveSlowRenders >= slowMediumThreshold) {
      stressScore += 0.32;
    } else if (perf.consecutiveSlowRenders >= slowLightThreshold) {
      stressScore += 0.12;
    }
    stressScore += Math.min(
      0.95,
      newBackpressureDrops * dropWeight + stalePerSec * staleWeight
    );
    const emaKeep = isHigh ? 0.88 : 0.84;
    const emaNew = 1 - emaKeep;
    state.stressEma =
      state.stressEma === 0 ? stressScore : state.stressEma * emaKeep + stressScore * emaNew;

    const hardBad =
      newBackpressureDrops >= hardBadBackpressure ||
      perf.consecutiveSlowRenders >= slowHardThreshold ||
      perf.avgRenderMs >= hardBadAvgMs;
    const bad = hardBad || state.stressEma >= stressBadThreshold;
    const good =
      !hardBad &&
      state.stressEma <= stressGoodThreshold &&
      perf.avgRenderMs > 0 &&
      perf.avgRenderMs <= avgGoodMs &&
      newBackpressureDrops === 0 &&
      stalePerSec < staleGoodThreshold;

    if (bad) {
      state.badWindows = Math.min(8, state.badWindows + 1);
      state.goodWindows = 0;
    } else if (good) {
      state.goodWindows = Math.min(12, state.goodWindows + 1);
      state.badWindows = 0;
      state.pendingDownscaleConfirmations = 0;
    } else {
      if (state.badWindows > 0) {
        state.badWindows -= 1;
      }
      if (state.goodWindows > 0) {
        state.goodWindows -= 1;
      }
      if (!bad && state.pendingDownscaleConfirmations > 0) {
        state.pendingDownscaleConfirmations -= 1;
      }
    }

    const bounds = this.getAdaptiveBounds();
    const canDecrease = now - state.lastAdjustMs >= ADAPTIVE_DECREASE_COOLDOWN_MS;
    const canIncrease = now - state.lastAdjustMs >= ADAPTIVE_INCREASE_COOLDOWN_MS;
    const prevBudgetScale = state.budgetScale;
    const prevDprScale = state.dprScale;

    let nextBudgetScale = state.budgetScale;
    let nextDprScale = state.dprScale;
    if (state.badWindows >= badWindowsTrigger && canDecrease) {
      state.pendingDownscaleConfirmations = Math.min(
        ADAPTIVE_DECREASE_CONFIRMATION_COUNT,
        state.pendingDownscaleConfirmations + 1
      );
      if (state.pendingDownscaleConfirmations >= ADAPTIVE_DECREASE_CONFIRMATION_COUNT) {
        const budgetDelta = bad ? budgetDownHard : budgetDownSoft;
        const dprDelta = bad ? dprDownHard : dprDownSoft;
        nextBudgetScale -= budgetDelta;
        nextDprScale -= dprDelta;
        state.badWindows = 0;
        state.pendingDownscaleConfirmations = 0;
        state.lastAdjustMs = now;
      } else {
        state.lastAdjustMs = now;
      }
    } else if (state.goodWindows >= goodWindowsTrigger && canIncrease) {
      nextBudgetScale += budgetUp;
      nextDprScale += dprUp;
      state.goodWindows = 0;
      state.pendingDownscaleConfirmations = 0;
      state.lastAdjustMs = now;
    } else if (
      !bad &&
      now - state.lastAdjustMs >= ADAPTIVE_RECOVERY_COOLDOWN_MS &&
      (state.budgetScale < 1 || state.dprScale < 1)
    ) {
      nextBudgetScale += budgetRecovery;
      nextDprScale += dprRecovery;
      state.pendingDownscaleConfirmations = 0;
      state.lastAdjustMs = now;
    }

    nextBudgetScale = clamp(nextBudgetScale, bounds.minBudgetScale, bounds.maxBudgetScale);
    nextDprScale = clamp(nextDprScale, bounds.minDprScale, bounds.maxDprScale);
    if (Math.abs(nextBudgetScale - 1) < 0.02) {
      nextBudgetScale = 1;
    }
    if (Math.abs(nextDprScale - 1) < 0.02) {
      nextDprScale = 1;
    }
    state.budgetScale = nextBudgetScale;
    state.dprScale = nextDprScale;
    state.lastBackpressureDrops = perf.droppedBackpressure;
    state.lastStaleDrops = perf.droppedStale;

    if (
      display === this.directSurfaceActiveDisplay &&
      (Math.abs(state.budgetScale - prevBudgetScale) >= 0.05 ||
        Math.abs(state.dprScale - prevDprScale) >= 0.05)
    ) {
      this.measureDirectSurfaceHost(true);
      this.refreshDirectSurfaceSizing(true);
    }
  }

  private syncWorkerRenderPolicy(): void {
    if (!this.worker || !this.workerReady) {
      return;
    }
    this.worker.postMessage({
      type: 'set_policy',
      renderQuality: this.renderQualityPreference,
      customQuality: this.customImageQuality,
      customFps: this.customFps
    });
  }

  private normalizeDisplay(display: number | null | undefined): number | null {
    const normalized = Math.floor(Number(display));
    if (!Number.isFinite(normalized) || normalized < 0) {
      return null;
    }
    return normalized;
  }

  private isActiveDisplay(display: number): boolean {
    const normalized = this.normalizeDisplay(display);
    return this.activeDisplay === null || normalized === this.activeDisplay;
  }

  private clearPendingFrame(display: number): void {
    const pending = this.pendingFrames.get(display);
    if (pending) {
      pending.close();
      this.pendingFrames.delete(display);
    }
    this.renderScheduled.delete(display);
  }

  private resetDisplayState(display: number): void {
    this.clearPendingFrame(display);
    this.clearDisplayCodecState(display);
    this.displayPerf.delete(display);
    this.adaptiveRenderState.delete(display);
    this.adaptiveStartupUntil.delete(display);
    this.lastFrameRenderedAt.delete(display);
    this.notifiedFrameSize.delete(display);
    this.canvases.delete(display);
    this.contexts.delete(display);
    this.softwareSourceCanvases.delete(display);
  }

  private clearInactiveDisplayState(activeDisplay: number | null): void {
    if (activeDisplay === null) {
      return;
    }
    for (const display of [...this.pendingFrames.keys()]) {
      if (display !== activeDisplay) {
        this.clearPendingFrame(display);
      }
    }
    for (const display of [...this.displayPerf.keys()]) {
      if (display !== activeDisplay) {
        this.displayPerf.delete(display);
      }
    }
    for (const display of [...this.adaptiveRenderState.keys()]) {
      if (display !== activeDisplay) {
        this.adaptiveRenderState.delete(display);
      }
    }
    for (const display of [...this.adaptiveStartupUntil.keys()]) {
      if (display !== activeDisplay) {
        this.adaptiveStartupUntil.delete(display);
      }
    }
    for (const display of [...this.lastFrameRenderedAt.keys()]) {
      if (display !== activeDisplay) {
        this.lastFrameRenderedAt.delete(display);
      }
    }
    for (const display of [...this.notifiedFrameSize.keys()]) {
      if (display !== activeDisplay) {
        this.notifiedFrameSize.delete(display);
      }
    }
    for (const display of [...this.canvases.keys()]) {
      if (display !== activeDisplay) {
        this.canvases.delete(display);
      }
    }
    for (const display of [...this.contexts.keys()]) {
      if (display !== activeDisplay) {
        this.contexts.delete(display);
      }
    }
    for (const display of [...this.softwareSourceCanvases.keys()]) {
      if (display !== activeDisplay) {
        this.softwareSourceCanvases.delete(display);
      }
    }
    this.clearInactiveCodecState(activeDisplay);
  }

  private clearInactiveCodecState(activeDisplay: number): void {
    const prefix = `${activeDisplay}:`;
    for (const [key, decoder] of this.decoders.entries()) {
      if (key.startsWith(prefix)) {
        continue;
      }
      try {
        decoder.close();
      } catch {
        // ignore
      }
      this.decoders.delete(key);
      this.decoderBooting.delete(key);
      this.pendingDecodeInputs.delete(key);
      this.decoderNeedsKeyFrame.delete(key);
      this.decoderLastPts.delete(key);
      this.decoderBackpressureOverflowState.delete(key);
      this.needRefreshLastSentAt.delete(key);
    }
    for (const [key, decoder] of this.softwareDecoders.entries()) {
      if (key.startsWith(prefix)) {
        continue;
      }
      void decoder.then((item) => item.close());
      this.softwareDecoders.delete(key);
      this.decoderNeedsKeyFrame.delete(key);
      this.decoderLastPts.delete(key);
      this.needRefreshLastSentAt.delete(key);
    }
    for (const key of [...this.decoderBooting.keys()]) {
      if (!key.startsWith(prefix)) {
        this.decoderBooting.delete(key);
      }
    }
    for (const key of [...this.pendingDecodeInputs.keys()]) {
      if (!key.startsWith(prefix)) {
        this.pendingDecodeInputs.delete(key);
      }
    }
    for (const key of [...this.decoderNeedsKeyFrame.keys()]) {
      if (!key.startsWith(prefix)) {
        this.decoderNeedsKeyFrame.delete(key);
      }
    }
    for (const key of [...this.decoderLastPts.keys()]) {
      if (!key.startsWith(prefix)) {
        this.decoderLastPts.delete(key);
      }
    }
    for (const key of [...this.decoderBackpressureOverflowState.keys()]) {
      if (!key.startsWith(prefix)) {
        this.decoderBackpressureOverflowState.delete(key);
      }
    }
    for (const key of [...this.needRefreshLastSentAt.keys()]) {
      if (!key.startsWith(prefix)) {
        this.needRefreshLastSentAt.delete(key);
      }
    }
  }

  private requestRefresh(display: number, decoderKey: string): void {
    if (!this.onNeedRefresh || !this.isActiveDisplay(display)) {
      return;
    }
    const now = Date.now();
    const last = this.needRefreshLastSentAt.get(decoderKey) ?? 0;
    if (now - last < 900) {
      return;
    }
    this.needRefreshLastSentAt.set(decoderKey, now);
    this.onNeedRefresh(display);
  }

  private syncWorkerActiveDisplay(reset = false): void {
    if (!this.worker || !this.workerReady || this.activeDisplay === null) {
      return;
    }
    const message: WorkerSetActiveDisplayMessage = {
      type: 'set_active_display',
      display: this.activeDisplay,
      reset
    };
    this.worker.postMessage(message);
  }

  private logDecodeError(err: unknown): void {
    const now = Date.now();
    if (now - this.lastDecodeErrorLogMs > 3000) {
      const suppressed = this.suppressedDecodeErrorCount;
      this.suppressedDecodeErrorCount = 0;
      this.lastDecodeErrorLogMs = now;
      if (suppressed > 0) {
        this.logger.error(`Video decode failed (${suppressed} suppressed)`, err);
      } else {
        this.logger.error('Video decode failed', err);
      }
      return;
    }
    this.suppressedDecodeErrorCount += 1;
  }

  private logDecoderError(err: unknown): void {
    const now = Date.now();
    if (now - this.lastDecoderErrorLogMs > 3000) {
      const suppressed = this.suppressedDecoderErrorCount;
      this.suppressedDecoderErrorCount = 0;
      this.lastDecoderErrorLogMs = now;
      if (suppressed > 0) {
        this.logger.error(`VideoDecoder error (${suppressed} suppressed)`, err);
      } else {
        this.logger.error('VideoDecoder error', err);
      }
      return;
    }
    this.suppressedDecoderErrorCount += 1;
  }

  private trackWorkerDecodeFailure(): void {
    if (!this.worker || !this.directSurfaceUseWorker) {
      return;
    }
    const now = Date.now();
    if (now - this.workerDecodeFailureWindowStart > 2000) {
      this.workerDecodeFailureWindowStart = now;
      this.workerDecodeFailureCount = 1;
      return;
    }
    this.workerDecodeFailureCount += 1;
    if (this.workerDecodeFailureCount < 24) {
      return;
    }
    this.logger.warn('Video worker decode unstable, fallback to main-thread decoding');
    this.workerUnavailable = true;
    this.shutdownWorker();
    if (this.activeDisplay !== null) {
      this.resetDisplayState(this.activeDisplay);
      this.onNeedRefresh?.(this.activeDisplay);
    }
  }
}

class SoftwareDecoder {
  private readonly ready: Promise<void>;
  private queue = Promise.resolve(true);

  constructor(
    private readonly display: number,
    private readonly module: OgvDecoderModule,
    private readonly logger: Logger,
    private readonly onFrame: (
      display: number,
      rgba: Uint8Array,
      width: number,
      height: number,
      displayWidth: number,
      displayHeight: number
    ) => void
  ) {
    this.ready = new Promise((resolve) => {
      this.module.init(() => resolve());
    });
  }

  close(): void {
    this.module.close();
  }

  async decode(input: DecodeInput): Promise<boolean> {
    await this.ready;
    this.queue = this.queue.then(() => this.decodeFrame(input));
    return this.queue;
  }

  private async decodeFrame(input: DecodeInput): Promise<boolean> {
    const ok = await new Promise<boolean>((resolve) => {
      this.module.processFrame(copyToArrayBuffer(input.data), (success) =>
        resolve(success)
      );
    });
    if (!ok) {
      if (input.key) {
        this.logger.warn(`Software ${input.codec} decoder rejected a key frame`);
      }
      return false;
    }
    const frame = this.module.frameBuffer;
    if (!frame) {
      return false;
    }
    try {
      const format = frame.format;
      const rgba = yuvToRgba(frame);
      const width = format.cropWidth || format.width;
      const height = format.cropHeight || format.height;
      const displayWidth = format.displayWidth || width;
      const displayHeight = format.displayHeight || height;
      this.onFrame(
        this.display,
        rgba,
        width,
        height,
        displayWidth,
        displayHeight
      );
      return true;
    } catch (err) {
      this.logger.error('Software video decode failed', err);
      return false;
    } finally {
      this.module.recycleFrame?.(frame);
    }
  }
}

function nowMs(): number {
  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    return performance.now();
  }
  return Date.now();
}

function canUseVideoWorker(): boolean {
  if (
    typeof Worker === 'undefined' ||
    typeof OffscreenCanvas === 'undefined' ||
    typeof HTMLCanvasElement === 'undefined'
  ) {
    return false;
  }
  if (typeof VideoDecoder === 'undefined') {
    return false;
  }
  return typeof HTMLCanvasElement.prototype.transferControlToOffscreen === 'function';
}

export async function detectDecodingSupport(): Promise<DecodingSupport> {
  const [vp8Web, vp9Web, av1Web, h264Web, h265Web] = await Promise.all([
    detectCodecSupport(CODEC_CONFIG.vp8),
    detectCodecSupport(CODEC_CONFIG.vp9),
    detectCodecSupport(CODEC_CONFIG.av1),
    detectCodecSupport(CODEC_CONFIG.h264),
    detectCodecSupport(CODEC_CONFIG.h265)
  ]);
  const [vp8Software, vp9Software, av1Software] = await Promise.all([
    vp8Web ? Promise.resolve(false) : hasSoftwareDecoder('vp8'),
    vp9Web ? Promise.resolve(false) : hasSoftwareDecoder('vp9'),
    av1Web ? Promise.resolve(false) : hasSoftwareDecoder('av1')
  ]);
  return {
    vp8: vp8Web || vp8Software,
    vp9: vp9Web || vp9Software,
    av1: av1Web || av1Software,
    h264: h264Web,
    h265: h265Web
  };
}

function normalizeRenderQualityPreference(value: string): RenderQualityPreference {
  switch (String(value ?? '').trim().toLowerCase()) {
    case 'low':
      return 'low';
    case 'best':
      return 'best';
    case 'custom':
      return 'custom';
    default:
      return 'balanced';
  }
}

async function hasSoftwareDecoder(codec: CodecType): Promise<boolean> {
  if (!SOFTWARE_DECODER_CONFIG[codec]) {
    return false;
  }
  let cached = SOFTWARE_DECODER_AVAILABILITY.get(codec);
  if (!cached) {
    cached = loadSoftwareDecoderSource(codec)
      .then(() => true)
      .catch(() => false);
    SOFTWARE_DECODER_AVAILABILITY.set(codec, cached);
  }
  return cached;
}

async function instantiateSoftwareDecoder(codec: CodecType): Promise<OgvDecoderModule> {
  const config = SOFTWARE_DECODER_CONFIG[codec];
  if (!config) {
    throw new Error(`software decoder is not available for ${codec}`);
  }
  const source = await loadSoftwareDecoderSource(codec);
  const scriptUrl = softwareDecoderScriptUrl(config.scriptName);
  const factory = new Function(
    `var _scriptDir = ${JSON.stringify(scriptUrl)};\n${source}\nreturn ${config.globalName};`
  );
  return await (factory() as Promise<OgvDecoderModule>);
}

function loadSoftwareDecoderSource(codec: CodecType): Promise<string> {
  const config = SOFTWARE_DECODER_CONFIG[codec];
  if (!config) {
    return Promise.reject(new Error(`unknown software decoder codec: ${codec}`));
  }
  let cached = SOFTWARE_DECODER_SOURCES.get(codec);
  if (!cached) {
    const url = softwareDecoderScriptUrl(config.scriptName);
    cached = fetch(url).then(async (response) => {
      if (!response.ok) {
        throw new Error(`failed to load ${config.scriptName}: ${response.status}`);
      }
      return response.text();
    });
    SOFTWARE_DECODER_SOURCES.set(codec, cached);
  }
  return cached;
}

function softwareDecoderScriptUrl(scriptName: string): string {
  return new URL(`../../ogvjs-1.8.6/${scriptName}`, import.meta.url).toString();
}

async function detectCodecSupport(candidates: string[]): Promise<boolean> {
  if (typeof VideoDecoder === 'undefined') {
    return false;
  }
  for (const codec of candidates) {
    try {
      const supported = await VideoDecoder.isConfigSupported({
        codec,
        optimizeForLatency: true
      });
      if (supported.supported) {
        return true;
      }
    } catch {
      // ignore
    }
  }
  return false;
}

function fitSurfaceToPixelBudget(
  width: number,
  height: number,
  maxPixels: number
): { width: number; height: number } {
  let nextWidth = Math.max(1, Math.floor(width));
  let nextHeight = Math.max(1, Math.floor(height));
  if (
    !Number.isFinite(nextWidth) ||
    !Number.isFinite(nextHeight) ||
    !Number.isFinite(maxPixels) ||
    maxPixels <= 0
  ) {
    return { width: 1, height: 1 };
  }
  const pixels = nextWidth * nextHeight;
  if (pixels <= maxPixels) {
    return { width: nextWidth, height: nextHeight };
  }
  const scale = Math.sqrt(maxPixels / pixels);
  nextWidth = Math.max(1, Math.floor(nextWidth * scale));
  nextHeight = Math.max(1, Math.floor(nextHeight * scale));
  return { width: nextWidth, height: nextHeight };
}

function applySamplingPolicy(
  ctx: Canvas2dContext | DirectCanvasContext,
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

function getCanvasContext(
  canvas: OffscreenCanvas | HTMLCanvasElement
): Canvas2dContext | null {
  return canvas.getContext('2d', {
    alpha: false,
    desynchronized: true,
    willReadFrequently: true
  }) as Canvas2dContext | null;
}

function writeRgbaToCanvas(
  ctx: Canvas2dContext,
  width: number,
  height: number,
  rgba: Uint8Array
): void {
  if (typeof ImageData !== 'undefined') {
    ctx.putImageData(new ImageData(new Uint8ClampedArray(rgba), width, height), 0, 0);
    return;
  }
  const imageData = ctx.createImageData(width, height);
  imageData.data.set(
    rgba.subarray(0, Math.min(imageData.data.byteLength, rgba.byteLength))
  );
  ctx.putImageData(imageData, 0, 0);
}

function copyToArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}

function yuvToRgba(frame: OgvFrameBuffer): Uint8Array {
  const { format, y, u, v } = frame;
  const cropLeft = format.cropLeft ?? 0;
  const cropTop = format.cropTop ?? 0;
  const width = format.cropWidth || format.width;
  const height = format.cropHeight || format.height;
  const chromaXShift = depower(format.width / format.chromaWidth);
  const chromaYShift = depower(format.height / format.chromaHeight);
  const rgba = new Uint8Array(width * height * 4);
  let offset = 0;
  for (let row = 0; row < height; row += 1) {
    const yRow = (cropTop + row) * y.stride;
    const uRow = ((cropTop + row) >> chromaYShift) * u.stride;
    const vRow = ((cropTop + row) >> chromaYShift) * v.stride;
    for (let col = 0; col < width; col += 1) {
      const yValue = y.bytes[yRow + cropLeft + col];
      const chromaCol = (cropLeft + col) >> chromaXShift;
      const cb = u.bytes[uRow + chromaCol];
      const cr = v.bytes[vRow + chromaCol];
      const scaled = 298 * yValue;
      rgba[offset++] = clampByte((scaled + 409 * cr - 57088) >> 8);
      rgba[offset++] = clampByte((scaled - 100 * cb - 208 * cr + 34816) >> 8);
      rgba[offset++] = clampByte((scaled + 516 * cb - 70912) >> 8);
      rgba[offset++] = 255;
    }
  }
  return rgba;
}

function depower(value: number): number {
  if (value <= 1) {
    return 0;
  }
  let shift = 0;
  let current = value;
  while (current > 1) {
    if (current % 2 !== 0) {
      throw new Error(`invalid chroma ratio: ${value}`);
    }
    current /= 2;
    shift += 1;
  }
  return shift;
}

function clampByte(value: number): number {
  if (value < 0) {
    return 0;
  }
  if (value > 255) {
    return 255;
  }
  return value;
}

function clamp(value: number, minValue: number, maxValue: number): number {
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

function isCanvas2dContext(value: unknown): value is Canvas2dContext {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  return 'drawImage' in value && 'getImageData' in value;
}

function isDirectCanvasContext(value: unknown): value is DirectCanvasContext {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  return 'drawImage' in value && 'clearRect' in value;
}
