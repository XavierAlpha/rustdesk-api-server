import * as fzstd from 'fzstd';
import { EventDispatcher } from '../core/events';
import { Logger } from '../core/logger';
import {
  SecretBoxCipher,
  createSymmetricKey,
  decodeBase64,
  encodeBase64,
  signOpen
} from './crypto';
import { concatBytes, sha256, utf8ToBytes } from './hash';
import { MessageInbox } from './inbox';
import { ProtoRoots, decodeProtoObject, loadProtos } from './proto';
import { ConnectionRoute, RelayInfo, RendezvousClient } from './rendezvous';
import { WebSocketTransport } from './transport';
import { ConnectRequest, ConnectionState, SessionContext, SessionMode } from './types';
import {
  RenderQualityPreference,
  VideoPipeline,
  detectDecodingSupport
} from './video';
import { MACOS_ISO_SWAP, USB_HID_TARGET_KEYCODES } from './keycode_maps';

type CodecProbe = {
  supported: boolean;
  smooth: boolean;
  powerEfficient: boolean;
  hardwareLikely: boolean;
};
type DecodingAbility = {
  vp8: boolean;
  vp9: boolean;
  av1: boolean;
  h264: boolean;
  h265: boolean;
  autoPrefer: SupportedDecodingPreferCodec;
  probes: {
    vp9: CodecProbe;
    av1: CodecProbe;
    h264: CodecProbe;
    h265: CodecProbe;
  };
};
type PeerEncoding = {
  vp8?: boolean;
  av1?: boolean;
  h264?: boolean;
  h265?: boolean;
};
type NormalizedDisplay = {
  x: number;
  y: number;
  width: number;
  height: number;
  cursor_embedded: number;
  original_width: number;
  original_height: number;
  scaled_width?: number;
};
type PeerInfoSnapshot = {
  version: string;
  username: string;
  hostname: string;
  platform: string;
  sasEnabled: boolean;
  currentDisplay: number;
  displays: NormalizedDisplay[];
  features: { privacyMode: boolean; terminal: boolean };
  resolutions: unknown;
  platformAdditions?: unknown;
};

type FileEntryInfo = {
  entryType: number;
  name: string;
  size: number;
  modifiedTime: number;
  isHidden?: boolean;
};

type UploadJob = {
  id: number;
  file: File;
  remotePath: string;
  fileNum: number;
  totalSize: number;
  sentBytes: number;
  started: boolean;
  cancelled: boolean;
  nextBlockId: number;
  startTime: number;
  lastProgressTime: number;
  lastProgressBytes: number;
  pendingStartTimer?: number;
  resumeOffset: number;
};

type DownloadJob = {
  id: number;
  remotePath: string;
  files: FileEntryInfo[];
  currentFileNum: number;
  chunks: Uint8Array[];
  receivedBytes: number;
  totalSize: number;
  startTime: number;
  lastProgressTime: number;
  lastProgressBytes: number;
  cancelled: boolean;
  confirmRetryTimer?: number;
};

enum SupportedDecodingPreferCodec {
  Auto = 0,
  VP9 = 1,
  H264 = 2,
  H265 = 3,
  VP8 = 4,
  AV1 = 5
}

enum BackNotificationState {
  BlkStateUnknown = 0,
  BlkOnSucceeded = 2,
  BlkOnFailed = 3,
  BlkOffSucceeded = 4,
  BlkOffFailed = 5
}

enum PrivacyModeState {
  PrvStateUnknown = 0,
  PrvOnByOther = 2,
  PrvNotSupported = 3,
  PrvOnSucceeded = 4,
  PrvOnFailedDenied = 5,
  PrvOnFailedPlugin = 6,
  PrvOnFailed = 7,
  PrvOffSucceeded = 8,
  PrvOffByPeer = 9,
  PrvOffFailed = 10,
  PrvOffUnknown = 11
}

enum BoolOption {
  NotSet = 0,
  No = 1,
  Yes = 2
}

enum ImageQuality {
  NotSet = 0,
  Low = 2,
  Balanced = 3,
  Best = 4
}

enum Chroma {
  I420 = 0,
  I444 = 1
}

const BUTTON_MASK: Record<string, number> = {
  left: 1,
  right: 2,
  wheel: 4,
  back: 8,
  forward: 16
};

function boolOption(value: boolean): BoolOption {
  return value ? BoolOption.Yes : BoolOption.No;
}

const MAX_AUTO_RECONNECT_ATTEMPTS = 3;
const AUTO_RECONNECT_BASE_DELAY_MS = 1200;
const INITIAL_VIDEO_REFRESH_DELAY_MS = 750;
const INITIAL_VIDEO_REFRESH_MAX_ATTEMPTS = 12;

export class WebSession {
  private readonly logger: Logger;
  private readonly events: EventDispatcher;
  private readonly transport: WebSocketTransport;
  private state: ConnectionState = 'idle';
  private readonly request: ConnectRequest;
  private proto?: ProtoRoots;
  private context?: SessionContext;
  private signedIdPk: Uint8Array = new Uint8Array();
  private hash?: { salt: string; challenge: string };
  private pendingLogin?: {
    password: string;
    osUsername: string;
    osPassword: string;
    remember: boolean;
  };
  private decoding?: DecodingAbility;
  private peerEncoding: PeerEncoding = {};
  private peerVersionNumber = 0;
  private supportsMultiUi = false;
  private isSecure = false;
  private readonly video: VideoPipeline;
  private readonly uploadJobs = new Map<number, UploadJob>();
  private readonly downloadJobs = new Map<number, DownloadJob>();
  private readonly qualityStats = new Map<number, { frames: number; bytes: number }>();
  private readonly peerInfoSnapshot: PeerInfoSnapshot = {
    version: '',
    username: '',
    hostname: '',
    platform: '',
    sasEnabled: false,
    currentDisplay: 0,
    displays: [],
    features: { privacyMode: false, terminal: false },
    resolutions: {}
  };
  private qualityTickTs = Date.now();
  private displayIds: number[] = [0];
  private currentDisplay = 0;
  private requestedDisplays: number[] = [];
  private lastDelayMs?: number;
  private lastTargetBitrate?: number;
  private lastCodecFormat?: string;
  private lastChroma = '4:2:0';
  private keepaliveTimer?: number;
  private initialVideoRefreshTimer?: number;
  private initialVideoRefreshDisplay: number | null = null;
  private initialVideoRefreshAttempts = 0;
  private firstDecodedVideoFrameSeen = false;
  private reconnectTimer?: number;
  private reconnectAttempts = 0;
  private closeNotified = false;
  private manualClose = false;
  private transportMessageOff?: () => void;

  constructor(request: ConnectRequest, events: EventDispatcher) {
    this.request = request;
    this.events = events;
    this.transport = new WebSocketTransport('session');
    this.logger = new Logger(`session:${request.id}`);
    this.video = new VideoPipeline(
      (display, rgba, width, height) => {
        if (typeof window.onRgba === 'function') {
          window.onRgba(display, rgba, width, height);
        }
      },
      (display, _width, _height) => {
        if (this.shouldRenderDisplay(display) && !this.firstDecodedVideoFrameSeen) {
          this.firstDecodedVideoFrameSeen = true;
          this.stopInitialVideoRefreshLoop();
        }
      },
      (display) => {
        if (this.isVideoSession() && this.shouldRenderDisplay(display)) {
          this.requestInitialVideoRefresh(display);
        }
      }
    );
    this.transport.onClose((event) => this.handleTransportClose(event));
  }

  private clearDownloadConfirmRetry(job?: DownloadJob): void {
    if (!job) {
      return;
    }
    if (job.confirmRetryTimer !== undefined) {
      window.clearTimeout(job.confirmRetryTimer);
      job.confirmRetryTimer = undefined;
    }
  }

  private scheduleDownloadConfirmRetry(job: DownloadJob, fileNum: number): void {
    if (job.cancelled || job.currentFileNum === fileNum) {
      return;
    }
    this.clearDownloadConfirmRetry(job);
    const tick = () => {
      if (
        job.cancelled ||
        job.currentFileNum === fileNum ||
        !this.downloadJobs.has(job.id)
      ) {
        this.clearDownloadConfirmRetry(job);
        return;
      }
      this.sendFileSendConfirm(job.id, fileNum, 0, false);
      job.confirmRetryTimer = window.setTimeout(tick, 600);
    };
    job.confirmRetryTimer = window.setTimeout(tick, 600);
  }

  getState(): ConnectionState {
    return this.state;
  }

  getPeerId(): string {
    return this.request.id;
  }

  attachVideoSurface(elementId: string): void {
    this.video.attachSurface(elementId);
  }

  detachVideoSurface(elementId?: string): void {
    this.video.detachSurface(elementId);
  }

  async connect(context: SessionContext, reconnecting = false): Promise<void> {
    this.manualClose = false;
    this.closeNotified = false;
    this.firstDecodedVideoFrameSeen = false;
    this.initialVideoRefreshAttempts = 0;
    this.stopInitialVideoRefreshLoop();
    if (!reconnecting) {
      this.reconnectAttempts = 0;
    }
    if (this.reconnectTimer !== undefined) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.detachTransportMessageHandler();
    this.context = context;
    this.video.setRenderQualityPreference(
      normalizeRenderQualityPreference(context.imageQuality)
    );
    this.state = 'connecting';
    this.events.emit({ name: 'conn_status', status: 'connecting' });
    try {
      this.proto = await loadProtos();
      this.logger.info(
        `Session context: version=${context.version || '-'}, buildDate=${context.buildDate || '-'}`
      );

      const directTarget = this.isDirectAccessTarget(this.request.id);
      const directEndpoint = this.resolveDirectAccessEndpoint(context);
      if (directEndpoint) {
        this.attachTransportMessageHandler();
        try {
          await this.connectDirectIpAccess(directEndpoint);
        } catch {
          this.transport.close();
          throw new Error(
            directEndpoint.startsWith('wss://')
              ? 'Direct IP access failed. Ensure target WSS endpoint is reachable and certificate is trusted.'
              : 'Direct IP access failed. Web client requires a reachable WS/WSS endpoint on target host.'
          );
        }
        this.state = 'connected';
        this.events.emit({ name: 'conn_status', status: 'connected' });
        this.events.emit({
          name: 'connection_ready',
          secure: 'false',
          direct: 'true',
          stream_type: 'TCP'
        });
        this.startKeepalive();
        this.startInitialVideoRefreshLoop();
        if (this.requestedDisplays.length > 0) {
          this.switchDisplay(this.requestedDisplays);
        }
        this.reconnectAttempts = 0;
        this.logger.info('Connected in direct IP access mode (unencrypted)');
        return;
      }
      if (directTarget && !context.allowDirectIpAccess) {
        throw new Error(
          'Direct IP access is disabled. Enable "Enable direct IP access" first.'
        );
      }

      if (!context.rendezvousServer) {
        throw new Error('Rendezvous server not configured');
      }

      const rendezvous = new RendezvousClient(
        {
          appName: context.myName,
          version: context.version,
          buildDate: context.buildDate,
          apiServer: context.apiServer,
          isPublicServer: true,
          rendezvousServers: [],
          relayServers: [],
          env: {},
          profile: { id: context.myId, name: context.myName },
          langs: []
        },
        this.proto,
        this.logger
      );

      const route = await rendezvous.requestConnectionRoute({
        peerId: this.request.id,
        relayServer: context.relayServer,
        rendezvousServer: context.rendezvousServer,
        defaultIdPort: context.defaultIdPort,
        apiServer: context.apiServer,
        key: context.key,
        token: context.token,
        connType: this.connTypeFromMode(this.request.mode),
        secure: true,
        forceRelay: Boolean(this.request.forceRelay),
        version: context.version
      });
      this.logger.info(
        `Route selected: ${route.kind === 'direct' ? 'direct' : 'relay'}`
      );
      const routeResult = await this.connectWithRoute(route, rendezvous, context);
      const isDirect = routeResult === 'direct';

      this.state = 'connected';
      this.events.emit({ name: 'conn_status', status: 'connected' });
      this.events.emit({
        name: 'connection_ready',
        secure: this.isSecure ? 'true' : 'false',
        direct: isDirect ? 'true' : 'false',
        stream_type: isDirect ? 'Direct' : 'Relay'
      });
      this.logger.info(
        `Connected (${isDirect ? 'direct' : 'relay'}, ${
          this.isSecure ? 'encrypted' : 'unencrypted'
        })`
      );

      this.attachTransportMessageHandler();
      this.startKeepalive();
      this.startInitialVideoRefreshLoop();
      if (this.requestedDisplays.length > 0) {
        this.switchDisplay(this.requestedDisplays);
      }
      this.reconnectAttempts = 0;
    } catch (err) {
      this.stopKeepalive();
      this.stopInitialVideoRefreshLoop();
      this.detachTransportMessageHandler();
      this.transport.setCipher(undefined);
      this.transport.close();
      this.state = 'idle';
      throw err;
    }
  }

  private resolveDirectAccessEndpoint(context: SessionContext): string | null {
    if (!context.allowDirectIpAccess) {
      return null;
    }
    const target = this.request.id.trim();
    if (!target || /^\d+$/.test(target)) {
      return null;
    }
    if (target.startsWith('ws://') || target.startsWith('wss://')) {
      return target;
    }
    if (target.includes('/') || target.includes('?') || target.includes('#')) {
      return null;
    }
    if (target.startsWith('[')) {
      const end = target.indexOf(']');
      if (end <= 0) {
        return null;
      }
      const host = target.slice(1, end);
      const rest = target.slice(end + 1);
      if (!host || !host.includes(':')) {
        return null;
      }
      if (!rest) {
        return `ws://[${host}]:${context.directAccessPort}`;
      }
      if (!rest.startsWith(':')) {
        return null;
      }
      const port = Number.parseInt(rest.slice(1), 10);
      if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        return null;
      }
      return `ws://[${host}]:${port}`;
    }
    const colonCount = (target.match(/:/g) ?? []).length;
    if (colonCount === 0) {
      if (isIpv4(target)) {
        return `ws://${target}:${context.directAccessPort}`;
      }
      return null;
    }
    if (colonCount === 1) {
      const lastColon = target.lastIndexOf(':');
      const host = target.slice(0, lastColon);
      const portRaw = target.slice(lastColon + 1);
      const port = Number.parseInt(portRaw, 10);
      if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
        return null;
      }
      if (!isIpv4(host) && !isDomain(host)) {
        return null;
      }
      return `ws://${host}:${port}`;
    }
    return null;
  }

  private isDirectAccessTarget(rawId: string): boolean {
    const target = rawId.trim();
    if (!target || /^\d+$/.test(target)) {
      return false;
    }
    if (target.startsWith('ws://') || target.startsWith('wss://')) {
      return true;
    }
    if (target.includes('/') || target.includes('?') || target.includes('#')) {
      return false;
    }
    if (target.startsWith('[')) {
      const end = target.indexOf(']');
      if (end <= 0) {
        return false;
      }
      const host = target.slice(1, end);
      const rest = target.slice(end + 1);
      if (!host || !host.includes(':')) {
        return false;
      }
      if (!rest) {
        return true;
      }
      if (!rest.startsWith(':')) {
        return false;
      }
      const port = Number.parseInt(rest.slice(1), 10);
      return Number.isInteger(port) && port > 0 && port <= 65535;
    }
    const colonCount = (target.match(/:/g) ?? []).length;
    if (colonCount === 0) {
      return isIpv4(target);
    }
    if (colonCount === 1) {
      const lastColon = target.lastIndexOf(':');
      const host = target.slice(0, lastColon);
      const portRaw = target.slice(lastColon + 1);
      const port = Number.parseInt(portRaw, 10);
      if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
        return false;
      }
      return isIpv4(host) || isDomain(host);
    }
    return false;
  }

  private async connectDirectIpAccess(endpoint: string): Promise<void> {
    await this.transport.connect(endpoint);
    this.isSecure = false;
    // Keep behavior aligned with native direct-IP mode (non-secure path).
    this.sendMessage({});
  }

  private async connectWithRoute(
    route: ConnectionRoute,
    rendezvous: RendezvousClient,
    context: SessionContext
  ): Promise<'direct' | 'relay'> {
    if (route.kind === 'direct') {
      try {
        await this.connectDirect(route.direct, context);
        return 'direct';
      } catch (err) {
        this.logger.warn('Direct connection failed, falling back to relay', err);
        this.transport.close();
      }
    }
    const relayInfo =
      route.kind === 'relay'
        ? route.relay
        : await rendezvous.requestRelay({
            peerId: this.request.id,
            relayServer: context.relayServer,
            rendezvousServer: context.rendezvousServer,
            defaultIdPort: context.defaultIdPort,
            apiServer: context.apiServer,
            key: context.key,
            token: context.token,
            connType: this.connTypeFromMode(this.request.mode),
            secure: true
          });
    await this.connectRelay(relayInfo, context);
    return 'relay';
  }

  private async connectDirect(
    direct: { endpoint: string; signedIdPk: Uint8Array },
    context: SessionContext
  ): Promise<void> {
    this.signedIdPk = direct.signedIdPk;
    this.logger.info(`Connecting direct via ${direct.endpoint}`);
    await this.transport.connect(direct.endpoint);
    const inbox = new MessageInbox(this.transport);
    try {
      await this.secureConnection(inbox, context);
    } finally {
      inbox.close();
    }
  }

  private async connectRelay(relayInfo: RelayInfo, context: SessionContext): Promise<void> {
    this.signedIdPk = relayInfo.signedIdPk;
    this.logger.info(`Connecting relay via ${relayInfo.relayEndpoint}`);
    await this.transport.connect(relayInfo.relayEndpoint);
    const inbox = new MessageInbox(this.transport);
    try {
      await this.sendRelayJoin(relayInfo.uuid, context);
      await this.secureConnection(inbox, context);
    } finally {
      inbox.close();
    }
  }

  close(): void {
    this.manualClose = true;
    if (this.reconnectTimer !== undefined) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.detachTransportMessageHandler();
    this.stopInitialVideoRefreshLoop();
    this.finalizeClosedState();
    this.transport.close();
  }

  sendBinary(data: Uint8Array): void {
    this.sendTransport(data);
  }

  requestDownload(
    id: number,
    path: string,
    includeHidden: boolean,
    fileNum = 0
  ): void {
    if (!this.proto) {
      return;
    }
    if (!path) {
      return;
    }
    const job: DownloadJob = {
      id,
      remotePath: path,
      files: [],
      currentFileNum: -1,
      chunks: [],
      receivedBytes: 0,
      totalSize: 0,
      startTime: Date.now(),
      lastProgressTime: Date.now(),
      lastProgressBytes: 0,
      cancelled: false
    };
    this.downloadJobs.set(id, job);
    this.sendMessage({
      fileAction: {
        send: {
          id,
          path,
          includeHidden,
          fileNum,
          fileType: 0
        }
      }
    });
  }

  startUpload(id: number, file: File, remotePath: string): void {
    if (!this.proto) {
      return;
    }
    if (!file || !remotePath) {
      return;
    }
    const modifiedTime = Math.floor((file.lastModified || Date.now()) / 1000);
    const entry: FileEntryInfo = {
      entryType: 4,
      name: '',
      size: file.size,
      modifiedTime,
      isHidden: false
    };
    const job: UploadJob = {
      id,
      file,
      remotePath,
      fileNum: 0,
      totalSize: file.size,
      sentBytes: 0,
      started: false,
      cancelled: false,
      nextBlockId: 0,
      startTime: Date.now(),
      lastProgressTime: Date.now(),
      lastProgressBytes: 0,
      resumeOffset: 0
    };
    this.uploadJobs.set(id, job);
    this.sendMessage({
      fileAction: {
        receive: {
          id,
          path: remotePath,
          files: [entry],
          fileNum: 0,
          totalSize: file.size
        }
      }
    });
    job.pendingStartTimer = window.setTimeout(() => {
      if (!job.started && !job.cancelled) {
        this.startUploadJob(job, 0);
      }
    }, 800);
  }

  login(payload: {
    password: string;
    osUsername?: string;
    osPassword?: string;
    remember?: boolean;
  }): void {
    this.pendingLogin = {
      password: payload.password ?? '',
      osUsername: payload.osUsername ?? '',
      osPassword: payload.osPassword ?? '',
      remember: payload.remember ?? false
    };
    if (this.hash) {
      void this.sendLoginWithHash();
    }
  }

  sendTwoFactor(code: string): void {
    if (!this.proto) {
      return;
    }
    const auth2Fa = { code };
    this.sendMessage({ auth2Fa });
  }

  inputString(value: string): void {
    if (!this.proto || !value) {
      return;
    }
    const keyEvent = {
      mode: 'Translate',
      press: true,
      seq: value
    };
    this.sendMessage({ keyEvent });
  }

  inputKey(payload: Record<string, unknown>): void {
    if (!this.proto) {
      return;
    }
    const name = String(payload.name ?? '');
    const modifiers = this.buildModifiers(payload);
    const down = payload.down === 'true' || payload.down === true;
    const press = payload.press === 'true' || payload.press === true;
    const controlKey = toControlKey(name);
    const keyEvent: Record<string, unknown> = {
      down,
      press,
      modifiers,
      mode: controlKey ? 'Legacy' : 'Translate'
    };
    if (controlKey) {
      keyEvent.controlKey = controlKey;
    } else if (name.length === 1) {
      keyEvent.seq = name;
    } else {
      keyEvent.seq = name;
    }
    this.sendMessage({ keyEvent });
  }

  flutterKeyEvent(payload: Record<string, unknown>): void {
    if (!this.proto) {
      return;
    }
    const name = String(payload.name ?? '');
    const usbHid = Number(payload.usb_hid ?? 0);
    const down = payload.down === 'true' || payload.down === true;
    if (name === 'flutter_key') {
      const controlKey = flutterSpecialKey(usbHid);
      if (!controlKey) {
        return;
      }
      this.sendMessage({
        keyEvent: {
          mode: 'Translate',
          controlKey,
          down
        }
      });
      return;
    }

    const isMapMode = this.isFlutterMapMode(payload);
    if (isMapMode) {
      const keyEvent = this.buildFlutterMapKeyEvent(payload, usbHid, down);
      if (keyEvent) {
        this.sendMessage({ keyEvent });
      }
      return;
    }

    if (down && name) {
      const keyEvent = {
        mode: 'Translate',
        seq: name,
        press: true
      };
      this.sendMessage({ keyEvent });
    }
  }

  private isFlutterMapMode(payload: Record<string, unknown>): boolean {
    const mode = String(payload.keyboard_mode ?? '')
      .trim()
      .toLowerCase();
    return mode === '' || mode === 'map';
  }

  private buildFlutterMapKeyEvent(
    payload: Record<string, unknown>,
    usbHid: number,
    down: boolean
  ): Record<string, unknown> | null {
    if (!Number.isFinite(usbHid) || usbHid <= 0) {
      return null;
    }
    const chr = this.resolveFlutterMapKeycode(usbHid, payload);
    if (chr === null) {
      return null;
    }
    const keyEvent: Record<string, unknown> = {
      mode: 'Map',
      chr,
      down
    };
    const mapping = USB_HID_TARGET_KEYCODES[usbHid];
    const lockModes = Number(payload.lock_modes ?? 0);
    const modifiers = buildFlutterLockModeModifiers(lockModes, mapping?.key);
    if (modifiers.length > 0) {
      keyEvent.modifiers = modifiers;
    }
    return keyEvent;
  }

  private resolveFlutterMapKeycode(
    usbHid: number,
    payload: Record<string, unknown>
  ): number | null {
    const mapping = USB_HID_TARGET_KEYCODES[usbHid];
    const platform = normalizeFlutterPeerPlatform(this.peerInfoSnapshot.platform);
    if (platform === 'ios') {
      return usbHid;
    }
    if (platform === 'unknown') {
      return null;
    }
    if (!mapping) {
      return null;
    }
    switch (platform) {
      case 'win':
        return normalizePlatformKeycode(mapping.win, false);
      case 'linux':
        return normalizePlatformKeycode(mapping.linux, false);
      case 'android':
        return normalizePlatformKeycode(mapping.android, false);
      case 'mac': {
        const code = normalizePlatformKeycode(mapping.mac, true);
        if (code === null) {
          return null;
        }
        const kbLayout = String(payload.kb_layout ?? '')
          .trim()
          .toUpperCase();
        if (kbLayout === 'ISO') {
          if (code === MACOS_ISO_SWAP.grave) {
            return MACOS_ISO_SWAP.section;
          }
          if (code === MACOS_ISO_SWAP.section) {
            return MACOS_ISO_SWAP.grave;
          }
        }
        return code;
      }
      default:
        return null;
    }
  }

  sendMouse(payload: Record<string, unknown>): void {
    if (!this.proto) {
      return;
    }
    const event = this.buildMouseEvent(payload);
    if (!event) {
      return;
    }
    const { mask, x, y, modifiers } = event;
    const mouseEvent = {
      mask,
      x,
      y,
      modifiers
    };
    this.sendMessage({ mouseEvent });
  }

  sendChat(text: string): void {
    if (!this.proto || !text) {
      return;
    }
    const misc = { chatMessage: { text } };
    this.sendMessage({ misc });
  }

  sendOption(option: Record<string, unknown>): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({ misc: { option } });
  }

  setImageQuality(value: string, customQuality?: number, customFps?: number): void {
    const renderQuality = normalizeRenderQualityPreference(value);
    this.video.setCustomQualityTuning(customQuality, customFps);
    this.video.setRenderQualityPreference(renderQuality);
    if (!this.proto) {
      return;
    }
    const option: Record<string, unknown> = {};
    const quality = parseImageQuality(renderQuality);
    if (quality !== null) {
      option.imageQuality = quality;
    }
    if (renderQuality === 'custom' && typeof customQuality === 'number') {
      option.customImageQuality = customQuality << 8;
      if (typeof customFps === 'number') {
        option.customFps = customFps;
      }
    } else if (renderQuality !== 'custom') {
      // Keep behavior aligned with native client:
      // switching out of custom quality restores non-custom FPS ceiling.
      option.customFps = 30;
    }
    if (Object.keys(option).length > 0) {
      this.sendOption(option);
    }
  }

  setCustomImageQuality(value: number, customFps?: number): void {
    this.video.setCustomQualityTuning(value, customFps);
    if (!this.proto) {
      return;
    }
    const option: Record<string, unknown> = {
      customImageQuality: value << 8
    };
    if (typeof customFps === 'number') {
      option.customFps = customFps;
    }
    this.sendOption(option);
  }

  setCustomFps(fps: number): void {
    this.video.setCustomQualityTuning(undefined, fps);
    if (!this.proto) {
      return;
    }
    this.sendOption({ customFps: fps });
  }

  async changePreferCodec(preference: string, preferI444 = false): Promise<void> {
    if (!this.proto) {
      return;
    }
    const decoding = await this.ensureDecoding();
    const prefer = normalizePreferCodec(preference, decoding);
    this.sendOption({
      supportedDecoding: {
        abilityVp9: decoding.vp9 ? 1 : 0,
        abilityH264: decoding.h264 ? 1 : 0,
        abilityAv1: decoding.av1 ? 1 : 0,
        abilityVp8: decoding.vp8 ? 1 : 0,
        abilityH265: decoding.h265 ? 1 : 0,
        prefer,
        preferChroma: preferI444 ? Chroma.I444 : Chroma.I420
      }
    });
    this.refreshVideo(this.currentDisplay);
  }

  togglePrivacyMode(implKey: string, on: boolean): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      misc: {
        togglePrivacyMode: {
          implKey,
          on
        }
      }
    });
  }

  toggleVirtualDisplay(index: number, on: boolean): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      misc: {
        toggleVirtualDisplay: {
          display: index,
          on
        }
      }
    });
  }

  lockScreen(): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      keyEvent: {
        mode: 'Legacy',
        controlKey: ControlKey.LockScreen,
        press: true,
        down: true
      }
    });
  }

  ctrlAltDel(): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      keyEvent: {
        mode: 'Legacy',
        controlKey: ControlKey.CtrlAltDel,
        press: true,
        down: true
      }
    });
  }

  switchDisplay(displays: number[]): void {
    if (!this.proto) {
      return;
    }
    const targets = displays
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value) && value >= 0)
      .map((value) => Math.floor(value));
    if (targets.length === 0) {
      return;
    }
    const target = [...new Set(targets)][0];
    this.requestedDisplays = [target];
    this.currentDisplay = target;
    this.video.switchDisplay(target);
    this.sendMessage({
      misc: {
        switchDisplay: {
          display: target
        }
      }
    });
    this.requestInitialVideoRefresh(target);
  }

  changeResolution(display: number, width: number, height: number): void {
    if (!this.proto) {
      return;
    }
    if (this.supportsMultiUi) {
      this.sendMessage({
        misc: {
          changeDisplayResolution: {
            display,
            resolution: {
              width,
              height
            }
          }
        }
      });
    } else {
      this.sendMessage({
        misc: {
          changeResolution: {
            width,
            height
          }
        }
      });
    }
  }

  refreshVideo(display?: number): void {
    if (!this.proto) {
      return;
    }
    if (this.supportsMultiUi) {
      const target =
        typeof display === 'number' && Number.isFinite(display) && display >= 0
          ? display
          : this.currentDisplay;
      this.sendMessage({
        misc: {
          refreshVideoDisplay: target
        }
      });
      return;
    }
    this.sendMessage({
      misc: {
        refreshVideo: true
      }
    });
  }

  selectSession(sid: number): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      misc: {
        selectedSid: sid
      }
    });
  }

  restartRemote(): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      misc: {
        restartRemoteDevice: true
      }
    });
  }

  elevateDirect(): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      misc: {
        elevationRequest: {
          direct: true
        }
      }
    });
  }

  elevateWithLogon(username: string, password: string): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      misc: {
        elevationRequest: {
          logon: {
            username,
            password
          }
        }
      }
    });
  }

  openTerminal(terminalId: number, rows: number, cols: number): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      terminalAction: {
        open: {
          terminalId,
          rows,
          cols
        }
      }
    });
  }

  sendTerminalInput(terminalId: number, data: string): void {
    if (!this.proto) {
      return;
    }
    const bytes = new TextEncoder().encode(data);
    this.sendMessage({
      terminalAction: {
        data: {
          terminalId,
          data: bytes,
          compressed: false
        }
      }
    });
  }

  resizeTerminal(terminalId: number, rows: number, cols: number): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      terminalAction: {
        resize: {
          terminalId,
          rows,
          cols
        }
      }
    });
  }

  closeTerminal(terminalId: number): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      terminalAction: {
        close: {
          terminalId
        }
      }
    });
  }

  readAllFiles(id: number, path: string, includeHidden: boolean): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      fileAction: {
        allFiles: {
          id,
          path,
          includeHidden
        }
      }
    });
  }

  readEmptyDirs(path: string, includeHidden: boolean): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      fileAction: {
        readEmptyDirs: {
          path,
          includeHidden
        }
      }
    });
  }

  cancelJob(id: number): void {
    if (!this.proto) {
      return;
    }
    const upload = this.uploadJobs.get(id);
    if (upload) {
      upload.cancelled = true;
      this.uploadJobs.delete(id);
    }
    const download = this.downloadJobs.get(id);
    if (download) {
      download.cancelled = true;
      this.clearDownloadConfirmRetry(download);
      this.downloadJobs.delete(id);
    }
    this.sendMessage({
      fileAction: {
        cancel: { id }
      }
    });
  }

  createDir(id: number, path: string): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      fileAction: {
        create: { id, path }
      }
    });
  }

  removeFile(id: number, path: string, fileNum: number): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      fileAction: {
        removeFile: {
          id,
          path,
          fileNum
        }
      }
    });
  }

  removeDir(id: number, path: string, recursive: boolean): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      fileAction: {
        removeDir: {
          id,
          path,
          recursive
        }
      }
    });
  }

  renameFile(id: number, path: string, newName: string): void {
    if (!this.proto) {
      return;
    }
    this.sendMessage({
      fileAction: {
        rename: {
          id,
          path,
          newName
        }
      }
    });
  }

  confirmOverrideFile(id: number, fileNum: number, needOverride: boolean): void {
    if (!this.proto) {
      return;
    }
    const skip = !needOverride;
    this.sendFileSendConfirm(id, fileNum, skip ? undefined : 0, skip);
    const job = this.uploadJobs.get(id);
    if (job && !skip) {
      this.startUploadJob(job, 0);
    }
    if (job && skip) {
      this.events.emit({
        name: 'job_error',
        id: String(id),
        file_num: String(fileNum),
        err: 'skipped'
      });
      this.uploadJobs.delete(id);
    }
  }

  getPeerEncoding(): PeerEncoding {
    return { ...this.peerEncoding };
  }

  getPeerVersionNumber(): number {
    return this.peerVersionNumber;
  }

  supportsMultiUiSession(): boolean {
    return this.supportsMultiUi;
  }

  getDecoding(): DecodingAbility | undefined {
    return this.decoding;
  }

  readRemoteDir(path: string, includeHidden: boolean): void {
    if (!this.proto) {
      return;
    }
    const fileAction = { readDir: { path, includeHidden } };
    this.sendMessage({ fileAction });
  }

  private async sendRelayJoin(uuid: string, context: SessionContext): Promise<void> {
    if (!this.proto) {
      return;
    }
    const requestRelay = {
      id: this.request.id,
      uuid,
      licenceKey: context.key ?? '',
      connType: this.connTypeFromMode(this.request.mode)
    };
    const payload = this.proto.rendezvousType.encode({ requestRelay }).finish();
    this.sendTransport(payload);
  }

  private async secureConnection(inbox: MessageInbox, context: SessionContext): Promise<void> {
    if (!this.proto) {
      throw new Error('Protocol is not initialized');
    }
    this.isSecure = false;
    if (!context.key) {
      throw new Error('Missing rendezvous public key');
    }
    if (!this.signedIdPk || this.signedIdPk.length === 0) {
      throw new Error(
        'Missing signed peer identity from rendezvous. Ensure the target is online and the ID server has a private key configured (RS_PRIV_KEY) matching your RS_PUB_KEY.'
      );
    }
    const rsPk = decodeBase64(context.key);
    let signPk: Uint8Array | null = null;
    const idPkBytes = signOpen(this.signedIdPk, rsPk);
    const idPk = decodeProtoObject<{ id?: string; pk?: Uint8Array }>(
      this.proto.idPkType,
      idPkBytes,
      {
        bytes: Uint8Array,
        defaults: false
      }
    );
    if (idPk.id === this.request.id && idPk.pk) {
      signPk = idPk.pk;
    }
    if (!signPk) {
      throw new Error('Rendezvous signature verification failed');
    }
    let first: Uint8Array;
    try {
      first = await inbox.next(15000);
    } catch (err) {
      if (err instanceof Error && err.message.includes('timeout')) {
        throw new Error(
          'Handshake timed out waiting for the peer. Ensure the target is online, ' +
            'registered on the same ID server, and supports secure connections.'
        );
      }
      throw err;
    }
    const msg = decodeProtoObject<Record<string, unknown>>(
      this.proto.messageType,
      first,
      {
        longs: String,
        bytes: Uint8Array,
        defaults: false
      }
    );
    const signedId = msg.signedId as { id?: Uint8Array } | undefined;
    if (!signedId || !signedId.id) {
      throw new Error('Peer did not provide a signed identity');
    }
    const peerIdPkBytes = signOpen(signedId.id, signPk);
    const peerIdPk = decodeProtoObject<{ id?: string; pk?: Uint8Array }>(
      this.proto.idPkType,
      peerIdPkBytes,
      {
        bytes: Uint8Array,
        defaults: false
      }
    );
    if (peerIdPk.id !== this.request.id || !peerIdPk.pk) {
      throw new Error('Peer identity verification failed');
    }
    const { publicKey, symmetricKey, sealed } = createSymmetricKey(peerIdPk.pk);
    this.sendMessage({
      publicKey: {
        asymmetricValue: publicKey,
        symmetricValue: sealed
      }
    });
    this.transport.setCipher(new SecretBoxCipher(symmetricKey));
    this.isSecure = true;
  }

  private async handleMessage(data: Uint8Array): Promise<void> {
    if (!this.proto) {
      return;
    }
    let msg: Record<string, unknown>;
    try {
      msg = decodeProtoObject<Record<string, unknown>>(
        this.proto.messageType,
        data,
        {
          longs: String,
          bytes: Uint8Array,
          defaults: false
        }
      );
    } catch (err) {
      this.logger.warn('Failed to decode message', err);
      return;
    }

    if (msg.hash) {
      this.handleHash(msg.hash as { salt?: string; challenge?: string });
    }
    if (msg.testDelay) {
      this.handleTestDelay(msg.testDelay as Record<string, unknown>);
    }
    if (msg.loginResponse) {
      this.handleLoginResponse(msg.loginResponse as Record<string, unknown>);
    }
    if (msg.peerInfo) {
      this.emitPeerInfoDelta(msg.peerInfo as Record<string, unknown>);
    }
    if (msg.videoFrame) {
      this.handleVideoFrame(msg.videoFrame as Record<string, unknown>);
    }
    if (msg.cursorData) {
      this.handleCursorData(msg.cursorData as Record<string, unknown>);
    }
    if (msg.cursorPosition) {
      this.handleCursorPosition(msg.cursorPosition as Record<string, unknown>);
    }
    if (msg.cursorId) {
      this.events.emit({ name: 'cursor_id', id: String(msg.cursorId) });
    }
    if (msg.clipboard) {
      this.handleClipboard(msg.clipboard as Record<string, unknown>);
    }
    if (msg.fileResponse) {
      this.handleFileResponse(msg.fileResponse as Record<string, unknown>);
    }
    if (msg.terminalResponse) {
      this.handleTerminalResponse(msg.terminalResponse as Record<string, unknown>);
    }
    if (msg.messageBox) {
      const box = msg.messageBox as Record<string, unknown>;
      this.events.emit({
        name: 'msgbox',
        type: String(box.msgtype ?? 'info'),
        title: String(box.title ?? ''),
        text: String(box.text ?? ''),
        link: String(box.link ?? '')
      });
    }
    if (msg.misc) {
      this.handleMisc(msg.misc as Record<string, unknown>);
    }
  }

  private handleHash(hash: { salt?: string; challenge?: string }): void {
    if (!hash.salt || !hash.challenge) {
      return;
    }
    this.hash = { salt: hash.salt, challenge: hash.challenge };
    if (this.pendingLogin || this.request.password) {
      void this.sendLoginWithHash();
      return;
    }
    this.events.emit({
      name: 'msgbox',
      type: 'input-password',
      title: 'Password Required',
      text: '',
      link: ''
    });
    // Keep behavior aligned with native clients: when no password is known yet,
    // send a login request with empty password so the remote side can prompt for approval.
    void this.sendLoginWithHash();
  }

  private async sendLoginWithHash(): Promise<void> {
    if (!this.proto || !this.hash || !this.context) {
      return;
    }
    const password =
      this.pendingLogin?.password ??
      this.request.password ??
      '';
    const osUsername = this.pendingLogin?.osUsername ?? '';
    const osPassword = this.pendingLogin?.osPassword ?? '';
    const passwordBytes = password
      ? await sha256(concatBytes(utf8ToBytes(password), utf8ToBytes(this.hash.salt)))
      : new Uint8Array();
    const finalHash = passwordBytes.length
      ? await sha256(concatBytes(passwordBytes, utf8ToBytes(this.hash.challenge)))
      : new Uint8Array();
    const loginRequest: Record<string, unknown> = {
      username: this.request.id,
      password: finalHash,
      myId: this.context.myId,
      myName: this.context.myName,
      myPlatform: this.context.platform,
      option: await this.buildOptionMessage(),
      sessionId: 0,
      version: this.context.version,
      osLogin: {
        username: osUsername,
        password: osPassword
      }
    };
    this.attachSessionMode(loginRequest);
    this.sendMessage({ loginRequest });
  }

  private async buildOptionMessage(): Promise<Record<string, unknown>> {
    const decoding = await this.ensureDecoding();
    const context = this.context;
    const prefer = normalizePreferCodec(
      context?.codecPreference ?? 'auto',
      decoding
    );
    const preferChroma = context?.preferI444 === true ? Chroma.I444 : Chroma.I420;
    const option: Record<string, unknown> = {
      supportedDecoding: {
        abilityVp9: decoding.vp9 ? 1 : 0,
        abilityH264: decoding.h264 ? 1 : 0,
        abilityAv1: decoding.av1 ? 1 : 0,
        abilityVp8: decoding.vp8 ? 1 : 0,
        abilityH265: decoding.h265 ? 1 : 0,
        prefer,
        preferChroma
      }
    };
    const qualityName = normalizeRenderQualityPreference(context?.imageQuality ?? 'balanced');
    const quality = parseImageQuality(qualityName);
    if (quality !== null) {
      option.imageQuality = quality;
    }
    if (qualityName === 'custom') {
      const customFps =
        Number.isFinite(context?.customFps) && Number(context?.customFps) > 0
          ? Math.round(Number(context?.customFps))
          : 60;
      option.customFps = customFps;
      const customQuality =
        Number.isFinite(context?.customImageQuality) &&
        Number(context?.customImageQuality) > 0
          ? Math.round(Number(context?.customImageQuality))
          : 100;
      option.customImageQuality = customQuality << 8;
    }
    return option;
  }

  private async ensureDecoding(): Promise<DecodingAbility> {
    if (!this.decoding) {
      this.decoding = await detectDecoding();
    }
    return this.decoding;
  }

  private handleLoginResponse(resp: Record<string, unknown>): void {
    if (resp.error) {
      const text = String(resp.error);
      const type = text.toLowerCase().includes('2fa')
        ? 'input-2fa'
        : text.toLowerCase().includes('password')
        ? 're-input-password'
        : 'error';
      this.events.emit({
        name: 'msgbox',
        type,
        title: 'Login Error',
        text,
        link: ''
      });
      return;
    }
    if (resp.peerInfo) {
      this.emitPeerInfo(resp.peerInfo as Record<string, unknown>);
    }
    if (resp.enableTrustedDevices !== undefined) {
      this.events.emit({
        name: 'enable_trusted_devices',
        value: String(resp.enableTrustedDevices)
      });
    }
    this.requestInitialVideoRefresh();
  }

  private emitPeerInfo(peerInfo: Record<string, unknown>): void {
    const pi = peerInfo as any;
    if (pi.version !== undefined) {
      this.peerInfoSnapshot.version = String(pi.version ?? '');
    }
    const version = this.peerInfoSnapshot.version;
    this.peerVersionNumber = getVersionNumber(version);
    this.supportsMultiUi = this.peerVersionNumber >= getVersionNumber('1.2.4');
    if (pi.encoding !== undefined) {
      this.peerEncoding = parsePeerEncoding(pi.encoding);
    }
    if (Array.isArray(pi.displays)) {
      const parsedDisplays: NormalizedDisplay[] = pi.displays.map((d: any) => ({
          x: Number(d.x ?? 0),
          y: Number(d.y ?? 0),
          width: Number(d.width ?? 0),
          height: Number(d.height ?? 0),
          cursor_embedded: d.cursorEmbedded ? 1 : 0,
          original_width: Number(d.originalResolution?.width ?? -1),
          original_height: Number(d.originalResolution?.height ?? -1),
          scaled_width:
            d.scale && Number(d.scale) > 0
              ? Math.round(Number(d.width ?? 0) / Number(d.scale))
              : undefined
        }));
      if (
        parsedDisplays.length > 0 ||
        this.peerInfoSnapshot.displays.length === 0
      ) {
        this.peerInfoSnapshot.displays = parsedDisplays;
      }
    }
    const displays = this.peerInfoSnapshot.displays;
    this.displayIds =
      displays.length > 0
        ? displays.map((_display: unknown, index: number) => index)
        : [0];
    this.video.setDisplayGeometries(displays);
    if (pi.currentDisplay !== undefined) {
      this.peerInfoSnapshot.currentDisplay = this.toFiniteNumber(
        pi.currentDisplay,
        this.peerInfoSnapshot.currentDisplay
      );
    }
    this.currentDisplay = this.peerInfoSnapshot.currentDisplay;
    this.video.setActiveDisplay(this.getActiveDisplay());
    if (pi.username !== undefined) {
      this.peerInfoSnapshot.username = String(pi.username ?? '');
    }
    if (pi.hostname !== undefined) {
      this.peerInfoSnapshot.hostname = String(pi.hostname ?? '');
    }
    if (pi.platform !== undefined) {
      this.peerInfoSnapshot.platform = String(pi.platform ?? '');
    }
    if (pi.sasEnabled !== undefined) {
      this.peerInfoSnapshot.sasEnabled = Boolean(pi.sasEnabled);
    }
    if (pi.features && typeof pi.features === 'object') {
      this.peerInfoSnapshot.features = {
        privacyMode: Boolean((pi.features as any).privacyMode),
        terminal: Boolean((pi.features as any).terminal)
      };
    }
    const features = this.peerInfoSnapshot.features;
    if (pi.resolutions !== undefined) {
      this.peerInfoSnapshot.resolutions = pi.resolutions ?? {};
    }
    const resolutions = this.peerInfoSnapshot.resolutions ?? {};
    if (pi.platformAdditions !== undefined) {
      this.peerInfoSnapshot.platformAdditions = pi.platformAdditions;
    }
    const platformAdditions = this.peerInfoSnapshot.platformAdditions;
    this.events.emit({
      name: 'peer_info',
      username: this.peerInfoSnapshot.username,
      hostname: this.peerInfoSnapshot.hostname,
      platform: this.peerInfoSnapshot.platform,
      sas_enabled: this.peerInfoSnapshot.sasEnabled ? 'true' : 'false',
      current_display: String(this.peerInfoSnapshot.currentDisplay),
      version,
      displays: JSON.stringify(displays),
      features: JSON.stringify({
        privacy_mode: features.privacyMode,
        terminal: features.terminal
      }),
      resolutions: JSON.stringify(resolutions),
      platform_additions:
        platformAdditions !== undefined && platformAdditions !== null
          ? JSON.stringify(platformAdditions)
        : ''
    });
    if (pi.windowsSessions && Array.isArray(pi.windowsSessions.sessions)) {
      const sessions = pi.windowsSessions.sessions.map((s: any) => ({
        sid: String(s.sid ?? ''),
        name: String(s.name ?? '')
      }));
      this.events.emit({
        name: 'set_multiple_windows_session',
        windows_sessions: JSON.stringify(sessions)
      });
    }
  }

  private emitPeerInfoDelta(peerInfo: Record<string, unknown>): void {
    const pi = peerInfo as any;
    if (Array.isArray(pi.displays)) {
      const displays: NormalizedDisplay[] = pi.displays.map((d: any) => ({
        x: Number(d.x ?? 0),
        y: Number(d.y ?? 0),
        width: Number(d.width ?? 0),
        height: Number(d.height ?? 0),
        cursor_embedded: d.cursorEmbedded ? 1 : 0,
        original_width: Number(d.originalResolution?.width ?? -1),
        original_height: Number(d.originalResolution?.height ?? -1),
        scaled_width:
          d.scale && Number(d.scale) > 0
            ? Math.round(Number(d.width ?? 0) / Number(d.scale))
            : undefined
      }));
      this.peerInfoSnapshot.displays = displays;
      this.displayIds =
        displays.length > 0
          ? displays.map((_display: unknown, index: number) => index)
          : [0];
      this.video.setDisplayGeometries(displays);
      this.events.emit({
        name: 'sync_peer_info',
        displays: JSON.stringify(displays)
      });
    }
    if (typeof pi.platformAdditions === 'string') {
      this.peerInfoSnapshot.platformAdditions = pi.platformAdditions;
      this.events.emit({
        name: 'sync_platform_additions',
        platform_additions: pi.platformAdditions
      });
    }
  }

  private handleVideoFrame(frame: Record<string, unknown>): void {
    const f = frame as any;
    const display = Number(f.display ?? 0);
    if (!this.shouldRenderDisplay(display)) {
      return;
    }
    if (f.vp8s) {
      const frames = (f.vp8s as any).frames as Array<Record<string, unknown>>;
      this.decodeFrames('vp8', display, frames);
      return;
    }
    if (f.vp9s) {
      const frames = (f.vp9s as any).frames as Array<Record<string, unknown>>;
      this.decodeFrames('vp9', display, frames);
      return;
    }
    if (f.av1s) {
      const frames = (f.av1s as any).frames as Array<Record<string, unknown>>;
      this.decodeFrames('av1', display, frames);
      return;
    }
    if (f.h264s) {
      const frames = (f.h264s as any).frames as Array<Record<string, unknown>>;
      this.decodeFrames('h264', display, frames);
      return;
    }
    if (f.h265s) {
      const frames = (f.h265s as any).frames as Array<Record<string, unknown>>;
      this.decodeFrames('h265', display, frames);
    }
  }

  private decodeFrames(
    codec: 'vp8' | 'vp9' | 'av1' | 'h264' | 'h265',
    display: number,
    frames: Array<Record<string, unknown>>
  ): void {
    let frameCount = 0;
    let frameBytes = 0;
    for (const entry of frames) {
      const data = entry.data as Uint8Array | undefined;
      if (!data) {
        continue;
      }
      frameCount += 1;
      frameBytes += data.byteLength;
      this.video.decode({
        codec,
        display,
        data,
        key: Boolean(entry.key),
        pts: entry.pts as number | string | undefined
      });
    }
    if (frameCount > 0) {
      this.updateQualityStats(display, codec, frameCount, frameBytes);
    }
  }

  private handleCursorData(data: Record<string, unknown>): void {
    const colors = data.colors as Uint8Array | undefined;
    if (!colors) {
      return;
    }
    const width = this.toFiniteNumber(data.width, 0);
    const height = this.toFiniteNumber(data.height, 0);
    const expectedBytes =
      width > 0 && height > 0 ? Math.floor(width) * Math.floor(height) * 4 : 0;
    let normalizedColors = colors;
    if (expectedBytes > 0 && normalizedColors.length !== expectedBytes) {
      try {
        const inflated = fzstd.decompress(normalizedColors);
        if (inflated.length === expectedBytes) {
          normalizedColors = inflated;
        }
      } catch {
        // Keep original bytes; downstream validation will drop malformed payloads.
      }
    }
    const colorsJson = JSON.stringify(Array.from(normalizedColors));
    this.events.emit({
      name: 'cursor_data',
      id: String(data.id ?? ''),
      hotx: String(data.hotx ?? 0),
      hoty: String(data.hoty ?? 0),
      width: String(width),
      height: String(height),
      colors: colorsJson
    });
  }

  private handleCursorPosition(data: Record<string, unknown>): void {
    this.events.emit({
      name: 'cursor_position',
      x: String(data.x ?? 0),
      y: String(data.y ?? 0)
    });
  }

  private handleClipboard(data: Record<string, unknown>): void {
    const format = Number(data.format ?? 0);
    if (format !== 0) {
      return;
    }
    const content = data.content as Uint8Array | undefined;
    if (!content) {
      return;
    }
    const text = new TextDecoder().decode(content);
    this.events.emit({ name: 'clipboard', content: text });
  }

  private handleFileResponse(resp: Record<string, unknown>): void {
    const response = resp as any;
    if (response.dir) {
      const dir = response.dir as any;
      const entries = Array.isArray(dir.entries)
        ? dir.entries.map((entry: any) => normalizeRemoteFileEntry(entry))
        : [];
      const jobId = Number(dir.id ?? 0);
      if (jobId > 0 && this.downloadJobs.has(jobId)) {
        const job = this.downloadJobs.get(jobId) as DownloadJob;
        job.files = entries.map((entry: any) => ({
          entryType: normalizeFileEntryType(entry.entry_type),
          name: String(entry.name ?? ''),
          size: Number(entry.size ?? 0),
          modifiedTime: Number(entry.modified_time ?? 0),
          isHidden: Boolean(entry.is_hidden)
        }));
        job.totalSize = job.files.reduce((sum, item) => sum + item.size, 0);
        this.events.emit({
          name: 'update_folder_files',
          info: JSON.stringify({
            id: jobId,
            num_entries: job.files.length,
            total_size: job.totalSize
          })
        });
        if (job.files.length > 0 && job.currentFileNum < 0) {
          this.sendFileSendConfirm(jobId, 0, 0, false);
          this.scheduleDownloadConfirmRetry(job, 0);
        }
      }
      const payload = {
        id: jobId,
        path: String(dir.path ?? ''),
        entries
      };
      this.events.emit({
        name: 'file_dir',
        value: JSON.stringify(payload),
        is_local: 'false'
      });
      return;
    }
    if (response.emptyDirs) {
      const empty = response.emptyDirs as any;
      const emptyDirs = Array.isArray(empty.emptyDirs)
        ? empty.emptyDirs.map((dir: any) => ({
            id: Number(dir.id ?? 0),
            path: String(dir.path ?? ''),
            entries: Array.isArray(dir.entries)
              ? dir.entries.map((entry: any) => normalizeRemoteFileEntry(entry))
              : []
          }))
        : [];
      const payload = {
        path: String(empty.path ?? ''),
        empty_dirs: emptyDirs
      };
      this.events.emit({
        name: 'empty_dirs',
        value: JSON.stringify(payload),
        is_local: 'false'
      });
      return;
    }
    if (response.error) {
      const err = response.error as any;
      this.events.emit({
        name: 'job_error',
        id: String(err.id ?? ''),
        err: String(err.error ?? 'Unknown error')
      });
      if (err.id !== undefined) {
        const id = Number(err.id);
        const upload = this.uploadJobs.get(id);
        if (upload) {
          upload.cancelled = true;
          this.uploadJobs.delete(id);
        }
        const download = this.downloadJobs.get(id);
        if (download) {
          download.cancelled = true;
          this.clearDownloadConfirmRetry(download);
          this.downloadJobs.delete(id);
        }
      }
      return;
    }
    if (response.digest) {
      this.handleFileDigest(response.digest as Record<string, unknown>);
      return;
    }
    if (response.block) {
      this.handleFileBlock(response.block as Record<string, unknown>);
      return;
    }
    if (response.done) {
      const done = response.done as any;
      this.handleFileDone(done as Record<string, unknown>);
    }
  }

  private handleFileDigest(digest: Record<string, unknown>): void {
    const id = Number(digest.id ?? 0);
    const fileNum = Number(digest.fileNum ?? 0);
    const isUpload = Boolean(digest.isUpload);
    if (isUpload) {
      const job = this.uploadJobs.get(id);
      if (!job) {
        return;
      }
      const offset = 0;
      this.sendFileSendConfirm(id, fileNum, offset, false);
      this.startUploadJob(job, offset);
      return;
    }
    if (this.downloadJobs.has(id)) {
      this.sendFileSendConfirm(id, fileNum, 0, false);
      this.scheduleDownloadConfirmRetry(this.downloadJobs.get(id) as DownloadJob, fileNum);
    }
  }

  private handleFileBlock(block: Record<string, unknown>): void {
    const id = Number(block.id ?? 0);
    const job = this.downloadJobs.get(id);
    if (!job || job.cancelled) {
      return;
    }
    const fileNum = Number(block.fileNum ?? 0);
    if (job.currentFileNum !== fileNum) {
      if (job.currentFileNum >= 0) {
        void this.finalizeDownloadFile(job, job.currentFileNum).catch((err) => {
          this.logger.warn('Failed to finalize previous web download file', err);
        });
      }
      job.chunks = [];
      job.currentFileNum = fileNum;
    }
    this.clearDownloadConfirmRetry(job);
    const compressed = Boolean(block.compressed);
    let data = normalizeDownloadChunk(block.data);
    if (!data || data.byteLength === 0) {
      return;
    }
    if (compressed) {
      try {
        data = normalizeDownloadChunk(fzstd.decompress(data));
      } catch (err) {
        this.clearDownloadConfirmRetry(job);
        this.events.emit({
          name: 'job_error',
          id: String(id),
          file_num: String(fileNum),
          err: 'decompress_failed'
        });
        this.downloadJobs.delete(id);
        return;
      }
      if (!data || data.byteLength === 0) {
        this.clearDownloadConfirmRetry(job);
        this.events.emit({
          name: 'job_error',
          id: String(id),
          file_num: String(fileNum),
          err: 'invalid_file_block'
        });
        this.downloadJobs.delete(id);
        return;
      }
    }
    job.chunks.push(data);
    job.receivedBytes += data.byteLength;
    this.emitJobProgress(id, fileNum, job.receivedBytes, job.startTime);
  }

  private handleFileDone(done: Record<string, unknown>): void {
    const id = Number(done.id ?? 0);
    const fileNum = Number(done.fileNum ?? 0);
    const job = this.downloadJobs.get(id);
    if (job && !job.cancelled) {
      this.clearDownloadConfirmRetry(job);
      const completedFileNum =
        job.currentFileNum >= 0 ? job.currentFileNum : Math.max(0, fileNum - 1);
      void this.completeDownloadJob(id, fileNum, job, completedFileNum);
      return;
    }
    this.events.emit({
      name: 'job_done',
      id: String(id),
      file_num: String(fileNum),
      speed: '0'
    });
  }

  private async completeDownloadJob(
    id: number,
    reportedFileNum: number,
    job: DownloadJob,
    completedFileNum: number
  ): Promise<void> {
    try {
      await this.finalizeDownloadFile(job, completedFileNum);
      const finalFinishedSize =
        job.totalSize > 0 ? job.totalSize : Math.max(job.receivedBytes, 0);
      if (finalFinishedSize > 0) {
        job.totalSize = Math.max(job.totalSize, finalFinishedSize);
        job.receivedBytes = Math.max(job.receivedBytes, finalFinishedSize);
        this.events.emit({
          name: 'job_progress',
          id: String(id),
          file_num: String(reportedFileNum),
          finished_size: String(Math.floor(finalFinishedSize)),
          speed: '0'
        });
      }
      this.events.emit({
        name: 'job_done',
        id: String(id),
        file_num: String(reportedFileNum),
        speed: '0'
      });
    } catch (err) {
      this.logger.warn('Failed to finalize web download', err);
      this.events.emit({
        name: 'job_error',
        id: String(id),
        file_num: String(reportedFileNum),
        err: 'download_save_failed'
      });
    } finally {
      this.clearDownloadConfirmRetry(job);
      this.downloadJobs.delete(id);
    }
  }

  private async finalizeDownloadFile(
    job: DownloadJob,
    fileNum: number
  ): Promise<void> {
    const entry = job.files[fileNum];
    if (job.chunks.length === 0 && entry?.size !== 0) {
      return;
    }
    const normalizedRemotePath = job.remotePath.replace(/\\/g, '/');
    const remoteBaseName =
      normalizedRemotePath.substring(normalizedRemotePath.lastIndexOf('/') + 1) ||
      job.remotePath;
    const baseName =
      (entry?.name && entry.name.trim().length > 0
        ? entry.name
        : remoteBaseName) || job.remotePath;
    const name = sanitizeFileName(baseName) || `download-${job.id}-${fileNum}`;
    const parts: BlobPart[] =
      job.chunks.length > 0
        ? job.chunks.map((chunk) => {
            const copy = new Uint8Array(chunk.byteLength);
            copy.set(chunk);
            return copy;
          })
        : [new Uint8Array(0)];
    const blob = new Blob(parts, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.rel = 'noopener noreferrer';
    link.style.display = 'none';
    document.body.appendChild(link);
    window.requestAnimationFrame(() => {
      try {
        link.dispatchEvent(
          new MouseEvent('click', {
            view: window,
            bubbles: true,
            cancelable: true
          })
        );
      } catch {
        link.click();
      }
      window.setTimeout(() => {
        if (link.parentNode) {
          link.parentNode.removeChild(link);
        }
      }, 1000);
    });
    window.setTimeout(() => URL.revokeObjectURL(url), 60000);
    job.chunks = [];
  }

  private emitJobProgress(
    id: number,
    fileNum: number,
    finishedSize: number,
    startTime: number
  ): void {
    const now = Date.now();
    const elapsed = Math.max((now - startTime) / 1000, 0.001);
    const speed = Math.floor(finishedSize / elapsed);
    this.events.emit({
      name: 'job_progress',
      id: String(id),
      file_num: String(fileNum),
      finished_size: String(Math.floor(finishedSize)),
      speed: String(speed)
    });
  }

  private sendFileSendConfirm(
    id: number,
    fileNum: number,
    offsetBlk?: number,
    skip?: boolean
  ): void {
    if (!this.proto) {
      return;
    }
    const payload: Record<string, unknown> = { id, fileNum };
    if (skip) {
      payload.skip = true;
    } else if (typeof offsetBlk === 'number') {
      payload.offsetBlk = offsetBlk;
    }
    this.sendMessage({
      fileAction: {
        sendConfirm: payload
      }
    });
  }

  private startUploadJob(job: UploadJob, offset: number): void {
    if (job.started || job.cancelled) {
      return;
    }
    if (job.pendingStartTimer) {
      window.clearTimeout(job.pendingStartTimer);
      job.pendingStartTimer = undefined;
    }
    job.started = true;
    job.resumeOffset = offset;
    job.sentBytes = offset;
    job.startTime = Date.now();
    job.lastProgressTime = job.startTime;
    job.lastProgressBytes = job.sentBytes;
    void this.sendUploadBlocks(job);
  }

  private async sendUploadBlocks(job: UploadJob): Promise<void> {
    const chunkSize = 128 * 1024;
    let offset = Math.max(0, job.resumeOffset);
    if (offset >= job.file.size) {
      this.sendMessage({
        fileResponse: {
          done: {
            id: job.id,
            fileNum: job.fileNum
          }
        }
      });
      this.events.emit({
        name: 'job_done',
        id: String(job.id),
        file_num: String(job.fileNum),
        speed: '0'
      });
      this.uploadJobs.delete(job.id);
      return;
    }
    while (offset < job.file.size) {
      if (job.cancelled) {
        return;
      }
      const slice = job.file.slice(offset, offset + chunkSize);
      const buffer = await slice.arrayBuffer();
      if (job.cancelled) {
        return;
      }
      const data = new Uint8Array(buffer);
      this.sendMessage({
        fileResponse: {
          block: {
            id: job.id,
            fileNum: job.fileNum,
            data,
            compressed: false,
            blkId: job.nextBlockId++
          }
        }
      });
      offset += data.length;
      job.sentBytes = offset;
      this.emitJobProgress(job.id, job.fileNum, job.sentBytes, job.startTime);
    }
    this.sendMessage({
      fileResponse: {
        done: {
          id: job.id,
          fileNum: job.fileNum
        }
      }
    });
    this.events.emit({
      name: 'job_done',
      id: String(job.id),
      file_num: String(job.fileNum),
      speed: '0'
    });
    this.uploadJobs.delete(job.id);
  }

  private handleTerminalResponse(resp: Record<string, unknown>): void {
    const response = resp as any;
    let type = '';
    let payload: Record<string, unknown> = {};
    if (response.opened) {
      const opened = response.opened as any;
      const terminalId = Number(opened.terminalId ?? 0);
      type = 'opened';
      payload = {
        terminal_id: terminalId,
        success: Boolean(opened.success),
        message: String(opened.message ?? ''),
        pid: Number(opened.pid ?? 0),
        service_id: String(opened.serviceId ?? ''),
        persistent_sessions: opened.persistentSessions ?? []
      };
    } else if (response.data) {
      const data = response.data as any;
      const terminalId = Number(data.terminalId ?? 0);
      let raw = this.normalizeTerminalBytes(data.data);
      if (!raw) {
        return;
      }
      if (Boolean(data.compressed)) {
        try {
          raw = fzstd.decompress(raw);
        } catch (err) {
          this.logger.warn('Failed to decompress terminal payload', err);
          return;
        }
      }
      type = 'data';
      payload = {
        terminal_id: terminalId,
        data: encodeBase64(raw)
      };
    } else if (response.closed) {
      const closed = response.closed as any;
      type = 'closed';
      payload = {
        terminal_id: Number(closed.terminalId ?? 0),
        exit_code: Number(closed.exitCode ?? 0)
      };
    } else if (response.error) {
      const err = response.error as any;
      type = 'error';
      payload = {
        terminal_id: Number(err.terminalId ?? 0),
        message: String(err.message ?? '')
      };
    }
    if (type) {
      this.events.emit({ name: 'terminal_response', type, ...payload });
    }
  }

  private normalizeTerminalBytes(value: unknown): Uint8Array | null {
    if (!value) {
      return null;
    }
    if (value instanceof Uint8Array) {
      return value;
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) {
      return Uint8Array.from(
        value.map((n) => {
          const byte = Number(n);
          return Number.isFinite(byte) ? byte & 0xff : 0;
        })
      );
    }
    if (typeof value === 'string') {
      try {
        const binary = atob(value);
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
          out[i] = binary.charCodeAt(i);
        }
        return out;
      } catch {
        return null;
      }
    }
    return null;
  }

  private handleMisc(misc: Record<string, unknown>): void {
    const payload = misc as any;
    if (payload.chatMessage) {
      const chat = payload.chatMessage as any;
      this.events.emit({
        name: 'chat_client_mode',
        text: String(chat.text ?? '')
      });
    }
    if (payload.switchDisplay) {
      const sw = payload.switchDisplay as any;
      const display = this.toFiniteNumber(sw.display, this.currentDisplay);
      const requestedDisplay = this.requestedDisplays[0];
      const shouldAdoptDisplay =
        requestedDisplay === undefined || requestedDisplay === display;
      if (shouldAdoptDisplay) {
        this.currentDisplay = display;
        this.peerInfoSnapshot.currentDisplay = display;
        this.video.setActiveDisplay(display);
        if (!this.displayIds.includes(display)) {
          this.displayIds = [...this.displayIds, display];
        }
        const originalResolution = sw.originalResolution as any;
        const snapshot = {
          x: this.toFiniteNumber(sw.x, 0),
          y: this.toFiniteNumber(sw.y, 0),
          width: this.toFiniteNumber(sw.width, 0),
          height: this.toFiniteNumber(sw.height, 0),
          cursorEmbedded: Boolean(sw.cursorEmbedded),
          originalWidth: this.toFiniteNumber(originalResolution?.width, -1),
          originalHeight: this.toFiniteNumber(originalResolution?.height, -1),
          resolutions: sw.resolutions ?? {}
        };
        this.events.emit({
          name: 'switch_display',
          display: String(display),
          x: String(snapshot.x),
          y: String(snapshot.y),
          width: String(snapshot.width),
          height: String(snapshot.height),
          cursor_embedded: snapshot.cursorEmbedded ? '1' : '0',
          original_width: String(snapshot.originalWidth),
          original_height: String(snapshot.originalHeight),
          resolutions: JSON.stringify(snapshot.resolutions ?? {})
        });
        this.requestInitialVideoRefresh();
      }
    }
    if (payload.permissionInfo) {
      const info = payload.permissionInfo as any;
      const name = permissionName(info.permission);
      if (name) {
        this.events.emit({
          name: 'permission',
          [name]: info.enabled ? 'true' : 'false'
        });
      }
    }
    if (payload.backNotification) {
      const back = payload.backNotification as any;
      if (back.privacyModeState !== undefined) {
        const state = Number(back.privacyModeState);
        const implKey = String(back.implKey ?? '');
        let privacyMode: 'on' | 'off' | undefined;
        let toastText = String(back.details ?? '').trim();

        switch (state) {
          case PrivacyModeState.PrvOnSucceeded:
            privacyMode = 'on';
            if (!toastText) {
              toastText = 'Enter privacy mode';
            }
            break;
          case PrivacyModeState.PrvNotSupported:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Unsupported';
            }
            break;
          case PrivacyModeState.PrvOnFailedDenied:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Peer denied';
            }
            break;
          case PrivacyModeState.PrvOnFailedPlugin:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Please install plugins';
            }
            break;
          case PrivacyModeState.PrvOnFailed:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Failed';
            }
            break;
          case PrivacyModeState.PrvOffSucceeded:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Exit privacy mode';
            }
            break;
          case PrivacyModeState.PrvOffByPeer:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Peer exit';
            }
            break;
          case PrivacyModeState.PrvOffUnknown:
            privacyMode = 'off';
            if (!toastText) {
              toastText = 'Turned off';
            }
            break;
          case PrivacyModeState.PrvOffFailed:
            if (!toastText) {
              toastText = 'Failed to turn off';
            }
            break;
          case PrivacyModeState.PrvOnByOther:
            if (!toastText) {
              toastText = 'Someone turns on privacy mode, exit';
            }
            break;
          default:
            break;
        }

        const event: { name: string; [key: string]: unknown } = {
          name: 'update_privacy_mode',
          privacy_mode_state: String(state),
          impl_key: implKey
        };
        if (privacyMode !== undefined) {
          event.privacy_mode = privacyMode;
        }
        this.events.emit(event);

        if (toastText) {
          this.events.emit({ name: 'toast', text: toastText });
        }
      }
      if (back.blockInputState !== undefined) {
        const state = Number(back.blockInputState);
        const on = state === BackNotificationState.BlkOnSucceeded;
        const off = state === BackNotificationState.BlkOffSucceeded;
        if (on || off) {
          this.events.emit({
            name: 'update_block_input_state',
            input_state: on ? 'on' : 'off'
          });
        }
      }
    }
    if (payload.followCurrentDisplay !== undefined) {
      this.events.emit({
        name: 'follow_current_display',
        display_idx: String(payload.followCurrentDisplay ?? 0)
      });
    }
    if (payload.portableServiceRunning !== undefined) {
      this.events.emit({
        name: 'portable_service_running',
        running: payload.portableServiceRunning ? 'true' : 'false'
      });
    }
    if (payload.clientRecordStatus !== undefined) {
      this.events.emit({
        name: 'record_status',
        start: payload.clientRecordStatus ? 'true' : 'false'
      });
    }
    if (payload.supportedEncoding) {
      this.peerEncoding = parsePeerEncoding(payload.supportedEncoding);
    }
    if (payload.closeReason) {
      this.events.emit({
        name: 'msgbox',
        type: 'error',
        title: 'Connection Error',
        text: String(payload.closeReason ?? ''),
        link: ''
      });
    }
  }

  private handleTestDelay(testDelay: Record<string, unknown>): void {
    const fromClient = testDelay.fromClient === true;
    if (fromClient) {
      return;
    }
    const time = testDelay.time;
    const delay = Number(testDelay.lastDelay ?? 0);
    const targetBitrate = Number(testDelay.targetBitrate ?? 0);
    if (Number.isFinite(delay) && delay >= 0) {
      this.lastDelayMs = Math.round(delay);
    }
    if (Number.isFinite(targetBitrate) && targetBitrate >= 0) {
      this.lastTargetBitrate = Math.round(targetBitrate);
    }
    this.events.emit({
      name: 'update_quality_status',
      delay: this.lastDelayMs !== undefined ? String(this.lastDelayMs) : '',
      target_bitrate:
        this.lastTargetBitrate !== undefined ? String(this.lastTargetBitrate) : ''
    });
    if (!this.proto) {
      return;
    }
    const echoDelay: Record<string, unknown> = {
      fromClient: false
    };
    if (time !== undefined && time !== null) {
      echoDelay.time = time;
    }
    if (Number.isFinite(delay) && delay >= 0) {
      echoDelay.lastDelay = Math.round(delay);
    }
    if (Number.isFinite(targetBitrate) && targetBitrate >= 0) {
      echoDelay.targetBitrate = Math.round(targetBitrate);
    }
    this.sendMessage({
      testDelay: echoDelay
    });
  }

  private updateQualityStats(
    display: number,
    codec: 'vp8' | 'vp9' | 'av1' | 'h264' | 'h265',
    frameCount: number,
    frameBytes: number
  ): void {
    const current = this.qualityStats.get(display) ?? { frames: 0, bytes: 0 };
    current.frames += frameCount;
    current.bytes += frameBytes;
    this.qualityStats.set(display, current);
    this.lastCodecFormat = codec.toUpperCase();

    const now = Date.now();
    const elapsedMs = now - this.qualityTickTs;
    if (elapsedMs < 1000) {
      return;
    }
    this.qualityTickTs = now;

    const fpsByDisplay: Record<string, number> = {};
    for (const id of this.displayIds) {
      fpsByDisplay[String(id)] = 0;
    }
    if (!(String(this.currentDisplay) in fpsByDisplay) && this.currentDisplay >= 0) {
      fpsByDisplay[String(this.currentDisplay)] = 0;
    }

    let totalBytes = 0;
    for (const [displayId, stats] of this.qualityStats.entries()) {
      const fps = Math.max(0, Math.round((stats.frames * 1000) / elapsedMs));
      fpsByDisplay[String(displayId)] = fps;
      totalBytes += stats.bytes;
      stats.frames = 0;
      stats.bytes = 0;
      this.qualityStats.set(displayId, stats);
    }
    if (Object.keys(fpsByDisplay).length === 0) {
      fpsByDisplay['0'] = 0;
    }

    const speed = `${((totalBytes * 1000) / elapsedMs / 1024).toFixed(2)}kB/s`;
    const event: any = {
      name: 'update_quality_status',
      speed,
      fps: JSON.stringify(fpsByDisplay),
      chroma: this.lastChroma
    };
    if (this.lastCodecFormat) {
      event.codec_format = this.lastCodecFormat;
    }
    if (this.lastDelayMs !== undefined) {
      event.delay = String(this.lastDelayMs);
    }
    if (this.lastTargetBitrate !== undefined && this.lastTargetBitrate > 0) {
      event.target_bitrate = String(this.lastTargetBitrate);
    } else if (totalBytes > 0) {
      // Fallback to measured stream throughput when peer does not report target bitrate.
      const estimatedKbps = Math.max(
        1,
        Math.round((totalBytes * 8 * 1000) / elapsedMs / 1024)
      );
      event.target_bitrate = String(estimatedKbps);
    }
    this.events.emit(event);
  }

  private attachTransportMessageHandler(): void {
    if (this.transportMessageOff) {
      return;
    }
    this.transportMessageOff = this.transport.onMessage((data) =>
      this.handleMessage(data)
    );
  }

  private detachTransportMessageHandler(): void {
    if (!this.transportMessageOff) {
      return;
    }
    this.transportMessageOff();
    this.transportMessageOff = undefined;
  }

  private sendTransport(data: Uint8Array): boolean {
    const sent = this.transport.send(data);
    if (sent) {
      return true;
    }
    const transportState = this.transport.getState();
    if (
      !this.manualClose &&
      this.state === 'connected' &&
      (transportState === 'closed' || transportState === 'error')
    ) {
      this.logger.warn(
        `Transport became unavailable while connected (state=${transportState})`
      );
    }
    return false;
  }

  private sendMessage(payload: Record<string, unknown>): void {
    if (!this.proto) {
      return;
    }
    const bytes = this.proto.messageType.encode(payload).finish();
    this.sendTransport(bytes);
  }

  private startKeepalive(): void {
    this.stopKeepalive();
    this.keepaliveTimer = window.setInterval(() => {
      this.sendClientHeartbeat();
    }, 10000);
  }

  private stopKeepalive(): void {
    if (this.keepaliveTimer !== undefined) {
      window.clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = undefined;
    }
  }

  private sendClientHeartbeat(): void {
    if (!this.proto || this.state !== 'connected') {
      return;
    }
    this.sendMessage({
      testDelay: {
        time: String(Date.now()),
        fromClient: true
      }
    });
  }

  private handleTransportClose(event: CloseEvent): void {
    if (this.manualClose || this.state === 'idle') {
      return;
    }
    if (this.state === 'connecting') {
      return;
    }
    if (this.shouldAutoReconnect(event)) {
      this.scheduleAutoReconnect();
      return;
    }
    const reason = this.describeCloseEvent(event);
    this.finalizeClosedState();
    if (reason) {
      this.events.emit({
        name: 'toast',
        text: `Connection closed: ${reason}`
      });
    }
  }

  private shouldAutoReconnect(event: CloseEvent): boolean {
    if (!this.context || this.manualClose) {
      return false;
    }
    if (this.state !== 'connected') {
      return false;
    }
    if (this.reconnectAttempts >= MAX_AUTO_RECONNECT_ATTEMPTS) {
      return false;
    }
    if (event.code === 1000 && event.wasClean) {
      return false;
    }
    return true;
  }

  private describeCloseEvent(event: CloseEvent): string {
    const reason = String(event.reason ?? '').trim();
    if (reason) {
      return reason;
    }
    const code = Number(event.code ?? 0);
    if (Number.isFinite(code) && code > 0) {
      return `code ${code}`;
    }
    return '';
  }

  private scheduleAutoReconnect(): void {
    const context = this.context;
    if (!context) {
      this.finalizeClosedState();
      return;
    }
    this.reconnectAttempts += 1;
    const attempt = this.reconnectAttempts;
    const delayMs = Math.min(AUTO_RECONNECT_BASE_DELAY_MS * attempt, 6000);
    this.stopKeepalive();
    this.state = 'connecting';
    this.events.emit({ name: 'conn_status', status: 'connecting' });
    this.events.emit({
      name: 'toast',
      text: `Connection lost, reconnecting (${attempt}/${MAX_AUTO_RECONNECT_ATTEMPTS})...`
    });
    if (this.reconnectTimer !== undefined) {
      window.clearTimeout(this.reconnectTimer);
    }
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.tryAutoReconnect(context, attempt);
    }, delayMs);
  }

  private async tryAutoReconnect(
    context: SessionContext,
    attempt: number
  ): Promise<void> {
    if (this.manualClose) {
      return;
    }
    try {
      await this.connect(context, true);
      this.events.emit({ name: 'toast', text: 'Reconnected successfully.' });
    } catch (err) {
      this.logger.warn(`Reconnect attempt ${attempt} failed`, err);
      if (this.manualClose) {
        return;
      }
      if (this.reconnectAttempts >= MAX_AUTO_RECONNECT_ATTEMPTS) {
        const reason =
          err instanceof Error && err.message
            ? err.message
            : 'Connection failed';
        this.finalizeClosedState();
        this.events.emit({
          name: 'toast',
          text: `Connection closed: ${reason}`
        });
        return;
      }
      this.scheduleAutoReconnect();
    }
  }

  private finalizeClosedState(): void {
    if (this.closeNotified) {
      return;
    }
    this.closeNotified = true;
    if (this.reconnectTimer !== undefined) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.reconnectAttempts = 0;
    this.stopKeepalive();
    this.stopInitialVideoRefreshLoop();
    this.detachTransportMessageHandler();
    this.state = 'closed';
    this.events.emit({ name: 'conn_status', status: 'closed' });
    this.video.detachSurface();
    this.video.close();
    for (const job of this.uploadJobs.values()) {
      job.cancelled = true;
    }
    this.uploadJobs.clear();
    for (const job of this.downloadJobs.values()) {
      job.cancelled = true;
    }
    this.downloadJobs.clear();
  }

  private isVideoSession(): boolean {
    return (
      this.request.mode === 'remote' ||
      this.request.mode === 'view-camera' ||
      this.request.mode === 'rdp'
    );
  }

  private startInitialVideoRefreshLoop(targetDisplay = this.getActiveDisplay()): void {
    this.stopInitialVideoRefreshLoop();
    if (!this.isVideoSession() || this.state !== 'connected' || !this.proto) {
      return;
    }
    this.initialVideoRefreshDisplay = targetDisplay;
    this.initialVideoRefreshAttempts = 0;
    this.firstDecodedVideoFrameSeen = false;
    const tick = () => {
      if (
        this.manualClose ||
        this.state !== 'connected' ||
        this.firstDecodedVideoFrameSeen ||
        !this.proto
      ) {
        this.stopInitialVideoRefreshLoop();
        return;
      }
      this.initialVideoRefreshAttempts += 1;
      this.refreshKnownDisplays();
      if (this.initialVideoRefreshAttempts >= INITIAL_VIDEO_REFRESH_MAX_ATTEMPTS) {
        this.stopInitialVideoRefreshLoop();
        return;
      }
      this.initialVideoRefreshTimer = window.setTimeout(
        tick,
        INITIAL_VIDEO_REFRESH_DELAY_MS
      );
    };
    tick();
  }

  private stopInitialVideoRefreshLoop(): void {
    if (this.initialVideoRefreshTimer !== undefined) {
      window.clearTimeout(this.initialVideoRefreshTimer);
      this.initialVideoRefreshTimer = undefined;
    }
    this.initialVideoRefreshDisplay = null;
  }

  private requestInitialVideoRefresh(display?: number): void {
    if (!this.isVideoSession() || this.manualClose || this.state !== 'connected' || !this.proto) {
      return;
    }
    if (
      display !== undefined &&
      Number.isFinite(display) &&
      display >= 0 &&
      !this.shouldRenderDisplay(Math.floor(display))
    ) {
      return;
    }
    const targetDisplay = this.getActiveDisplay();
    this.refreshKnownDisplays();
    if (
      this.initialVideoRefreshTimer !== undefined &&
      this.initialVideoRefreshDisplay === targetDisplay
    ) {
      return;
    }
    this.startInitialVideoRefreshLoop(targetDisplay);
  }

  private refreshKnownDisplays(): void {
    if (!this.proto) {
      return;
    }
    const target = this.getActiveDisplay();
    if (target === null) {
      this.refreshVideo();
      return;
    }
    this.refreshVideo(target);
  }

  private getActiveDisplay(): number | null {
    if (this.requestedDisplays.length > 0) {
      const display = this.requestedDisplays[0];
      if (Number.isFinite(display) && display >= 0) {
        return display;
      }
    }
    if (Number.isFinite(this.currentDisplay) && this.currentDisplay >= 0) {
      return this.currentDisplay;
    }
    return null;
  }

  private shouldRenderDisplay(display: number): boolean {
    const activeDisplay = this.getActiveDisplay();
    return activeDisplay === null || activeDisplay === display;
  }

  private toFiniteNumber(value: unknown, fallback: number): number {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  private connTypeFromMode(mode: SessionMode): number {
    switch (mode) {
      case 'file-transfer':
        return 1;
      case 'port-forward':
        return 2;
      case 'rdp':
        return 3;
      case 'view-camera':
        return 4;
      case 'terminal':
        return 5;
      default:
        return 0;
    }
  }

  private attachSessionMode(loginRequest: Record<string, unknown>): void {
    switch (this.request.mode) {
      case 'file-transfer':
        loginRequest.fileTransfer = { dir: '', showHidden: false };
        break;
      case 'view-camera':
        loginRequest.viewCamera = {};
        break;
      case 'terminal':
        loginRequest.terminal = {};
        break;
      default:
        break;
    }
  }

  private buildModifiers(payload: Record<string, unknown>): number[] {
    const modifiers: number[] = [];
    if (payload.alt === 'true' || payload.alt === true) {
      modifiers.push(ControlKey.Alt);
    }
    if (payload.ctrl === 'true' || payload.ctrl === true) {
      modifiers.push(ControlKey.Control);
    }
    if (payload.shift === 'true' || payload.shift === true) {
      modifiers.push(ControlKey.Shift);
    }
    if (payload.command === 'true' || payload.command === true) {
      modifiers.push(ControlKey.Meta);
    }
    return modifiers;
  }

  private buildMouseEvent(payload: Record<string, unknown>): {
    mask: number;
    x: number;
    y: number;
    modifiers: number[];
  } | null {
    const type = typeof payload.type === 'string' ? payload.type : 'move';
    const x = Number(payload.x ?? 0);
    const y = Number(payload.y ?? 0);
    const relativeMarker = payload.relative_mouse_mode;
    if (relativeMarker !== undefined && relativeMarker !== null) {
      const active = ['1', 'Y', 'on', 'true'].includes(String(relativeMarker));
      if (!active) {
        return null;
      }
      if (type !== 'move_relative') {
        return null;
      }
      if (x !== 0 || y !== 0) {
        return null;
      }
      if (
        payload.buttons !== undefined ||
        payload.alt !== undefined ||
        payload.ctrl !== undefined ||
        payload.shift !== undefined ||
        payload.command !== undefined
      ) {
        return null;
      }
    }
    const typeValue = mouseTypeValue(type);
    const buttons = normalizeButtons(payload.buttons);
    const mask = typeValue | (buttons << 3);
    return { mask, x, y, modifiers: this.buildModifiers(payload) };
  }
}

const CODEC_CANDIDATES = {
  vp9: ['vp09.00.10.08', 'vp09.01.10.08'],
  av1: ['av01.0.08M.08', 'av01.0.04M.08'],
  h264: ['avc1.42E01E', 'avc1.4D401E', 'avc1.64001F'],
  h265: ['hvc1.1.6.L93.B0', 'hvc1.1.6.L120.B0', 'hev1.1.6.L93.B0', 'hev1.1.6.L120.B0']
} as const;

const CODEC_MEDIA_TYPES = {
  vp9: ['video/webm; codecs="vp09.00.10.08"', 'video/webm; codecs="vp09.01.10.08"'],
  av1: ['video/mp4; codecs="av01.0.08M.08"', 'video/webm; codecs="av01.0.08M.08"'],
  h264: [
    'video/mp4; codecs="avc1.42E01E"',
    'video/mp4; codecs="avc1.4D401E"',
    'video/mp4; codecs="avc1.64001F"'
  ],
  h265: ['video/mp4; codecs="hvc1.1.6.L93.B0"', 'video/mp4; codecs="hev1.1.6.L93.B0"']
} as const;

function emptyCodecProbe(): CodecProbe {
  return {
    supported: false,
    smooth: false,
    powerEfficient: false,
    hardwareLikely: false
  };
}

async function detectCodecSupport(
  candidates: readonly string[]
): Promise<{ supported: boolean; hardwareLikely: boolean }> {
  if (typeof VideoDecoder === 'undefined') {
    return { supported: false, hardwareLikely: false };
  }
  for (const codec of candidates) {
    try {
      const preferHardware = await VideoDecoder.isConfigSupported({
        codec,
        optimizeForLatency: true,
        hardwareAcceleration: 'prefer-hardware'
      });
      if (preferHardware.supported) {
        return { supported: true, hardwareLikely: true };
      }
    } catch {
      // ignore and fallback
    }
    try {
      const supported = await VideoDecoder.isConfigSupported({
        codec,
        optimizeForLatency: true
      });
      if (supported.supported) {
        return { supported: true, hardwareLikely: false };
      }
    } catch {
      // ignore
    }
  }
  return { supported: false, hardwareLikely: false };
}

async function detectMediaDecodingInfo(mediaTypes: readonly string[]): Promise<{
  smooth: boolean;
  powerEfficient: boolean;
}> {
  const mediaCapabilities =
    typeof navigator !== 'undefined' && 'mediaCapabilities' in navigator
      ? navigator.mediaCapabilities
      : undefined;
  if (!mediaCapabilities || typeof mediaCapabilities.decodingInfo !== 'function') {
    return { smooth: false, powerEfficient: false };
  }
  let smooth = false;
  let powerEfficient = false;
  for (const contentType of mediaTypes) {
    try {
      const info = await mediaCapabilities.decodingInfo({
        type: 'file',
        video: {
          contentType,
          width: 1920,
          height: 1080,
          bitrate: 4_000_000,
          framerate: 30
        }
      });
      if (!info.supported) {
        continue;
      }
      smooth = smooth || Boolean(info.smooth);
      powerEfficient = powerEfficient || Boolean(info.powerEfficient);
      if (smooth && powerEfficient) {
        break;
      }
    } catch {
      // ignore
    }
  }
  return { smooth, powerEfficient };
}

async function detectCodecProbe(
  candidates: readonly string[],
  mediaTypes: readonly string[]
): Promise<CodecProbe> {
  const support = await detectCodecSupport(candidates);
  if (!support.supported) {
    return emptyCodecProbe();
  }
  const mediaInfo = await detectMediaDecodingInfo(mediaTypes);
  return {
    supported: true,
    smooth: mediaInfo.smooth,
    powerEfficient: mediaInfo.powerEfficient,
    hardwareLikely: support.hardwareLikely
  };
}

function pickAutoPreferCodec(
  probes: DecodingAbility['probes']
): SupportedDecodingPreferCodec {
  const h265 = probes.h265;
  if (h265.supported && (h265.hardwareLikely || h265.smooth || h265.powerEfficient)) {
    return SupportedDecodingPreferCodec.H265;
  }
  const h264 = probes.h264;
  if (h264.supported && (h264.hardwareLikely || h264.smooth || h264.powerEfficient)) {
    return SupportedDecodingPreferCodec.H264;
  }
  const vp9 = probes.vp9;
  if (vp9.supported && (vp9.hardwareLikely || vp9.smooth || vp9.powerEfficient)) {
    return SupportedDecodingPreferCodec.VP9;
  }
  const av1 = probes.av1;
  if (av1.supported && (av1.hardwareLikely || av1.powerEfficient)) {
    return SupportedDecodingPreferCodec.AV1;
  }
  if (h265.supported) {
    return SupportedDecodingPreferCodec.H265;
  }
  if (h264.supported) {
    return SupportedDecodingPreferCodec.H264;
  }
  if (vp9.supported) {
    return SupportedDecodingPreferCodec.VP9;
  }
  if (av1.supported) {
    return SupportedDecodingPreferCodec.AV1;
  }
  return SupportedDecodingPreferCodec.Auto;
}

async function detectDecoding(): Promise<DecodingAbility> {
  const base = await detectDecodingSupport();
  if (typeof VideoDecoder === 'undefined') {
    const probes = {
      vp9: emptyCodecProbe(),
      av1: emptyCodecProbe(),
      h264: emptyCodecProbe(),
      h265: emptyCodecProbe()
    };
    return {
      vp8: base.vp8,
      vp9: base.vp9,
      av1: base.av1,
      h264: base.h264,
      h265: base.h265,
      autoPrefer: SupportedDecodingPreferCodec.Auto,
      probes
    };
  }
  const [vp9, av1, h264, h265] = await Promise.all([
    detectCodecProbe(CODEC_CANDIDATES.vp9, CODEC_MEDIA_TYPES.vp9),
    detectCodecProbe(CODEC_CANDIDATES.av1, CODEC_MEDIA_TYPES.av1),
    detectCodecProbe(CODEC_CANDIDATES.h264, CODEC_MEDIA_TYPES.h264),
    detectCodecProbe(CODEC_CANDIDATES.h265, CODEC_MEDIA_TYPES.h265)
  ]);
  const probes = { vp9, av1, h264, h265 };
  return {
    vp8: base.vp8,
    vp9: base.vp9 || vp9.supported,
    av1: base.av1 || av1.supported,
    h264: base.h264 || h264.supported,
    h265: base.h265 || h265.supported,
    autoPrefer: pickAutoPreferCodec(probes),
    probes
  };
}

const ControlKey = {
  Alt: 1,
  Backspace: 2,
  CapsLock: 3,
  Control: 4,
  Delete: 5,
  DownArrow: 6,
  End: 7,
  Escape: 8,
  F1: 9,
  F10: 10,
  F11: 11,
  F12: 12,
  F2: 13,
  F3: 14,
  F4: 15,
  F5: 16,
  F6: 17,
  F7: 18,
  F8: 19,
  F9: 20,
  Home: 21,
  LeftArrow: 22,
  Meta: 23,
  PageDown: 25,
  PageUp: 26,
  Return: 27,
  RightArrow: 28,
  Shift: 29,
  Space: 30,
  Tab: 31,
  UpArrow: 32,
  Insert: 58,
  NumLock: 63,
  VolumeMute: 76,
  VolumeUp: 77,
  VolumeDown: 78,
  Power: 79,
  CtrlAltDel: 100,
  LockScreen: 101
};

const NAME_TO_CONTROL_KEY: Record<string, number> = {
  enter: ControlKey.Return,
  return: ControlKey.Return,
  tab: ControlKey.Tab,
  escape: ControlKey.Escape,
  esc: ControlKey.Escape,
  backspace: ControlKey.Backspace,
  delete: ControlKey.Delete,
  del: ControlKey.Delete,
  home: ControlKey.Home,
  end: ControlKey.End,
  pageup: ControlKey.PageUp,
  pagedown: ControlKey.PageDown,
  left: ControlKey.LeftArrow,
  arrowleft: ControlKey.LeftArrow,
  right: ControlKey.RightArrow,
  arrowright: ControlKey.RightArrow,
  up: ControlKey.UpArrow,
  arrowup: ControlKey.UpArrow,
  down: ControlKey.DownArrow,
  arrowdown: ControlKey.DownArrow,
  space: ControlKey.Space,
  capslock: ControlKey.CapsLock,
  shift: ControlKey.Shift,
  ctrl: ControlKey.Control,
  control: ControlKey.Control,
  alt: ControlKey.Alt,
  meta: ControlKey.Meta,
  command: ControlKey.Meta,
  insert: ControlKey.Insert,
  f1: ControlKey.F1,
  f2: ControlKey.F2,
  f3: ControlKey.F3,
  f4: ControlKey.F4,
  f5: ControlKey.F5,
  f6: ControlKey.F6,
  f7: ControlKey.F7,
  f8: ControlKey.F8,
  f9: ControlKey.F9,
  f10: ControlKey.F10,
  f11: ControlKey.F11,
  f12: ControlKey.F12
};

function toControlKey(name: string): number | null {
  const normalized = name.toLowerCase().replace(/\s+/g, '');
  const key = NAME_TO_CONTROL_KEY[normalized];
  return key ?? null;
}

function flutterSpecialKey(usbHid: number): number | null {
  switch (usbHid) {
    case 0x007f:
      return ControlKey.VolumeMute;
    case 0x0080:
      return ControlKey.VolumeUp;
    case 0x0081:
      return ControlKey.VolumeDown;
    case 0x0066:
      return ControlKey.Power;
    default:
      return null;
  }
}

function normalizeFlutterPeerPlatform(
  platform: string
): 'win' | 'linux' | 'mac' | 'android' | 'ios' | 'unknown' {
  const normalized = platform.trim().toLowerCase();
  if (normalized.startsWith('win')) {
    return 'win';
  }
  if (normalized.startsWith('linux')) {
    return 'linux';
  }
  if (normalized.startsWith('mac')) {
    return 'mac';
  }
  if (normalized.startsWith('android')) {
    return 'android';
  }
  if (normalized.startsWith('ios')) {
    return 'ios';
  }
  return 'unknown';
}

function normalizePlatformKeycode(
  code: number | undefined,
  allowZero: boolean
): number | null {
  if (typeof code !== 'number' || !Number.isFinite(code)) {
    return null;
  }
  if (!allowZero && code <= 0) {
    return null;
  }
  return Math.trunc(code);
}

function buildFlutterLockModeModifiers(
  lockModes: number,
  keyName?: string
): number[] {
  if (!Number.isFinite(lockModes) || !keyName) {
    return [];
  }
  const modifiers: number[] = [];
  if (/^Key[A-Z]$/.test(keyName) && (lockModes & (1 << 1)) !== 0) {
    modifiers.push(ControlKey.CapsLock);
  }
  if (
    /^Kp(?:[0-9]|Decimal|Divide|Multiply|Minus|Plus|Return|Equal|Comma)$/.test(
      keyName
    ) &&
    (lockModes & (1 << 2)) !== 0
  ) {
    modifiers.push(ControlKey.NumLock);
  }
  return modifiers;
}

function mouseTypeValue(type: string): number {
  switch (type) {
    case 'down':
      return 1;
    case 'up':
      return 2;
    case 'wheel':
      return 3;
    case 'trackpad':
      return 4;
    case 'move_relative':
      return 5;
    default:
      return 0;
  }
}

function normalizeButtons(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim().toLowerCase();
    if (trimmed in BUTTON_MASK) {
      return BUTTON_MASK[trimmed];
    }
    const parsed = Number(trimmed);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return 0;
}

function parseImageQuality(value: string): ImageQuality | null {
  switch (value) {
    case 'low':
      return ImageQuality.Low;
    case 'balanced':
      return ImageQuality.Balanced;
    case 'best':
      return ImageQuality.Best;
    default:
      return null;
  }
}

function normalizeRenderQualityPreference(value: unknown): RenderQualityPreference {
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

function normalizePreferCodec(
  value: string,
  decoding: DecodingAbility
): SupportedDecodingPreferCodec {
  const normalized = value.trim().toLowerCase();
  switch (normalized) {
    case 'auto':
      return decoding.autoPrefer;
    case 'vp9':
      return decoding.vp9 ? SupportedDecodingPreferCodec.VP9 : SupportedDecodingPreferCodec.Auto;
    case 'h264':
      return decoding.h264 ? SupportedDecodingPreferCodec.H264 : SupportedDecodingPreferCodec.Auto;
    case 'av1':
      return decoding.av1 ? SupportedDecodingPreferCodec.AV1 : SupportedDecodingPreferCodec.Auto;
    case 'vp8':
      return decoding.vp8 ? SupportedDecodingPreferCodec.VP8 : SupportedDecodingPreferCodec.Auto;
    case 'h265':
      return decoding.h265 ? SupportedDecodingPreferCodec.H265 : SupportedDecodingPreferCodec.Auto;
    default:
      return SupportedDecodingPreferCodec.Auto;
  }
}

function parsePeerEncoding(value: unknown): PeerEncoding {
  if (!value || typeof value !== 'object') {
    return {};
  }
  const enc = value as Record<string, unknown>;
  return {
    vp8: Boolean(enc.vp8),
    av1: Boolean(enc.av1),
    h264: Boolean(enc.h264),
    h265: Boolean(enc.h265)
  };
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) {
    return false;
  }
  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }
    const num = Number.parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

function isDomain(value: string): boolean {
  if (!value || value.length > 253) {
    return false;
  }
  if (value.includes('..') || value.startsWith('-') || value.endsWith('-')) {
    return false;
  }
  return /^[A-Za-z0-9.-]+$/.test(value);
}

function permissionName(value: unknown): string | null {
  const code = Number(value ?? -1);
  switch (code) {
    case 0:
      return 'keyboard';
    case 2:
      return 'clipboard';
    case 3:
      return 'audio';
    case 4:
      return 'file';
    case 5:
      return 'restart';
    case 6:
      return 'recording';
    case 7:
      return 'block_input';
    default:
      return null;
  }
}

function getVersionNumber(v: string): number {
  const [base, patch] = v.split('-', 2);
  let n = 0;
  let last = 0;
  for (const part of base.split('.')) {
    last = Number(part) || 0;
    n = n * 1000 + last;
  }
  n = n - last + last * 10;
  if (patch) {
    n += Number(patch) || 0;
  }
  return n;
}

function normalizeDownloadChunk(data: unknown): Uint8Array | null {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    const view = data as ArrayBufferView;
    const copy = new Uint8Array(view.byteLength);
    copy.set(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
    return copy;
  }
  if (Array.isArray(data)) {
    return Uint8Array.from(
      data.map((value) => Math.max(0, Math.min(255, Number(value) || 0)))
    );
  }
  return null;
}

function sanitizeFileName(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return 'download.bin';
  }
  const normalized = trimmed.replace(/^[\\/]+/, '');
  const safe = normalized.replace(/[\\/]/g, '_');
  const cleaned = safe.replace(/[<>:"/\\|?*\u0000-\u001F]/g, '_');
  return cleaned || 'download.bin';
}

function normalizeFileEntryType(value: unknown): number {
  return Number.isFinite(Number(value)) ? Math.trunc(Number(value)) : 0;
}

function normalizeRemoteFileEntry(entry: Record<string, unknown>): Record<string, unknown> {
  return {
    entry_type: normalizeFileEntryType(entry.entryType ?? entry.entry_type),
    name: String(entry.name ?? ''),
    is_hidden: Boolean(entry.isHidden ?? entry.is_hidden),
    size: Number(entry.size ?? 0),
    modified_time: Number(entry.modifiedTime ?? entry.modified_time ?? 0)
  };
}
