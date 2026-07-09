import { loadConfig, RuntimeConfig } from '../core/config';
import { EventDispatcher } from '../core/events';
import { Logger } from '../core/logger';
import { detectOs, screenInfo } from '../core/platform';
import { StorageStore } from '../core/storage';
import { generateUuid } from '../core/uuid';
import {
  decryptLocalSecret,
  encryptLocalSecret
} from './crypto';
import { MessageInbox } from './inbox';
import { decodeProtoObject, loadProtos, ProtoRoots } from './proto';
import { checkWsEndpoint } from './rendezvous';
import { WebSession } from './session';
import { WebSocketTransport } from './transport';
import { ConnectRequest, SessionContext, SessionMode } from './types';

type OptionPayload = { name?: string; value?: unknown };
type AccountAuthPayload = { op?: string; remember?: boolean };
type AccountAuthResult = {
  state_msg: string;
  failed_msg: string;
  url?: string;
  url_launched?: boolean;
  auth_body?: unknown;
};
type OidcAuthUrlResponse = { code?: string; url?: string; error?: string };
type OidcAuthQueryResponse = {
  error?: string;
  access_token?: string;
  type?: string;
  user?: { name?: string; status?: unknown };
  [key: string]: unknown;
};
type BootstrapConfigPayload = {
  appName?: string;
  version?: string;
  buildDate?: string;
  apiServer?: string;
  rendezvousServers?: string[] | string;
  relayServers?: string[] | string;
  rsPubKey?: string;
  isPublicServer?: boolean;
  env?: Record<string, unknown>;
};
type DroppedFilePayload = {
  uri?: string;
  name?: string;
  mime_type?: string;
  last_modified?: number;
  relative_path?: string;
};

type ConnectionCandidate = {
  rendezvousServer: string;
  relayServer: string;
};

const FALLBACK_DEFAULT_ID_PORT = 21116;

export class WebRuntime {
  private readonly config: RuntimeConfig;
  private readonly store: StorageStore;
  private readonly events: EventDispatcher;
  private readonly logger: Logger;
  private readonly optionDefaults = new Map<string, string>();
  private readonly localOptionDefaults = new Map<string, string>();
  private readonly flutterLocalOptionDefaults = new Map<string, string>();
  private readonly userDefaultOptionDefaults = new Map<string, string>();
  private currentSession?: WebSession;
  private initialized = false;
  private nextFileHandle = 1;
  private readonly fileHandles = new Map<number, File[]>();
  private protoPromise?: Promise<ProtoRoots>;
  private accountAuthNonce = 0;
  private accountAuthAbort?: AbortController;
  private accountAuthPopup: Window | null = null;
  private connectStatusTimer?: number;
  private connectStatusDebounceTimer?: number;
  private cleanupHandlersBound = false;
  private inputSource1PointerInside = false;
  private readonly inputSource1PressedKeys = new Map<string, string>();
  private videoSurfaceElementId = '';
  private queryOnlinesInFlight = false;
  private pendingOnlineQueryIds?: string[];
  private onlineQueryTransport?: WebSocketTransport;
  private onlineQueryEndpoint = '';
  private onlineQueryCloseTimer?: number;
  private connectStatusProbeInFlight = false;

  constructor() {
    this.config = loadConfig();
    this.store = new StorageStore('camellia.web.');
    this.events = new EventDispatcher();
    this.logger = new Logger('runtime', this.isDebug());
    this.refreshDefaultOptions();
  }

  init(): void {
    if (this.initialized) {
      if (typeof window.onInitFinished === 'function') {
        window.onInitFinished();
      }
      return;
    }
    this.initialized = true;
    this.logger.info('Initializing web runtime');
    this.bindEventSinks();
    this.bindInputSource1Handlers();
    this.store.ensure('uuid', generateUuid);
    this.store.ensure('my_name', () => this.config.profile.name);
    this.store.ensure('my_id', () => this.ensureMyId());
    this.store.remove('temporary_password');
    this.store.remove('permanent_password');
    this.syncRecentPeersStoreFormat();
    this.bindCleanupHandlers();
    this.startConnectStatusProbe();
    if (typeof window.onInitFinished === 'function') {
      window.onInitFinished();
    }
  }

  setByName(name: string, arg0?: unknown, arg1?: unknown): string {
    switch (name) {
      case 'session_add_sync':
        return this.handleSessionAdd(arg0);
      case 'session_start':
        this.handleSessionStart(arg0);
        return '';
      case 'session_close':
      case 'close':
        this.inputSource1PointerInside = false;
        this.releaseInputSource1PressedKeys();
        this.currentSession?.detachVideoSurface(this.videoSurfaceElementId);
        this.currentSession?.close();
        this.closeOnlineQueryTransport();
        return '';
      case 'attach_video_surface':
        if (typeof arg0 === 'string') {
          const elementId = arg0.trim();
          if (elementId) {
            this.videoSurfaceElementId = elementId;
            this.currentSession?.attachVideoSurface(elementId);
          }
        }
        return '';
      case 'detach_video_surface': {
        const elementId = typeof arg0 === 'string' ? arg0.trim() : '';
        if (
          !elementId ||
          !this.videoSurfaceElementId ||
          this.videoSurfaceElementId === elementId
        ) {
          this.currentSession?.detachVideoSurface(this.videoSurfaceElementId);
          this.videoSurfaceElementId = '';
        }
        return '';
      }
      case 'reconnect':
        this.reconnect();
        return '';
      case 'refresh':
        if (this.currentSession) {
          const display = Number(arg0);
          this.currentSession.refreshVideo(
            Number.isFinite(display) && display >= 0 ? display : undefined
          );
        }
        return '';
      case 'option:toggle':
        return this.toggleOption(String(arg0 ?? ''));
      case 'option:session':
      case 'option:local':
      case 'option:peer':
      case 'option:flutter:peer':
      case 'option:flutter:local':
      case 'option:user:default':
        if (name === 'option:peer') {
          this.setPeerOptionPayload(arg0);
        } else {
          this.setOptionPayload(name, arg0, arg1);
        }
        return '';
      case 'option':
        this.setOptionPayload('option', arg0, arg1);
        return '';
      case 'common':
        this.setCommonPayload(arg0);
        return '';
      case 'my_id': {
        const trimmed = String(arg0 ?? '').trim();
        const next = trimmed || this.generateNumericId();
        this.store.set('my_id', next);
        return '';
      }
      case 'options':
        this.setOptionsPayload(arg0);
        return '';
      case 'bootstrap_config':
        this.applyBootstrapConfig(arg0);
        return '';
      case 'fav':
        this.store.set('fav', arg0 ?? '');
        return '';
      case 'remove_peer':
        if (typeof arg0 === 'string') {
          this.removePeerById(arg0);
        }
        return '';
      case 'save_ab':
        this.store.set('address_book', arg0 ?? '');
        return '';
      case 'clear_ab':
        this.store.set('address_book', '');
        return '';
      case 'save_group':
        this.store.set('groups', arg0 ?? '');
        return '';
      case 'clear_group':
        this.store.set('groups', '');
        return '';
      case 'remember':
        this.store.set('remember', arg0 ?? 'false');
        return '';
      case 'envvar':
        if (typeof arg0 === 'string' && arg0.trim().startsWith('{')) {
          const payload = this.safeJson(arg0) as OptionPayload;
          if (typeof payload.name === 'string') {
            this.setEnvValue(payload.name, payload.value ?? '');
          }
        } else if (typeof arg0 === 'string') {
          this.setEnvValue(arg0, arg1 ?? '');
        }
        return '';
      case 'cursor':
        if (typeof arg0 === 'string') {
          const trimmed = arg0.trim();
          if (trimmed.startsWith('{')) {
            const payload = this.safeJson(arg0);
            const url = String(payload.url ?? '');
            const hotx = Number(payload.hotx ?? 0);
            const hoty = Number(payload.hoty ?? 0);
            if (url) {
              document.body.style.cursor = `url(${url}) ${hotx} ${hoty}, auto`;
            } else {
              document.body.style.cursor = 'auto';
            }
          } else {
            document.body.style.cursor = arg0;
          }
        }
        return '';
      case 'enter_or_leave':
        this.inputSource1PointerInside = this.parseBoolLike(arg0);
        if (!this.inputSource1PointerInside) {
          this.releaseInputSource1PressedKeys();
        }
        return '';
      case 'flutter_key_event':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0);
          this.applyLocalFlutterKeyOptions(payload);
          payload.keyboard_mode =
            this.getScopedOption('option:session', 'keyboard_mode') || 'map';
          payload.kb_layout = this.getScopedOption('option:local', 'kb_layout');
          this.currentSession.flutterKeyEvent(payload);
        }
        return '';
      case 'flutter_raw_key_event':
        if (this.currentSession && typeof arg0 === 'string') {
          this.handleFlutterRawKeyEvent(this.safeJson(arg0));
        }
        return '';
      case 'send_mouse':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0);
          this.applyLocalMouseOptions(payload);
          this.currentSession.sendMouse(payload);
        }
        return '';
      case 'send_pointer':
        if (this.currentSession && typeof arg0 === 'string') {
          this.handlePointerPayload(this.safeJson(arg0));
        }
        return '';
      case 'input_string':
        if (this.currentSession && typeof arg0 === 'string') {
          this.currentSession.inputString(arg0);
        }
        return '';
      case 'input_key':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0);
          this.applyLocalKeyOptions(payload);
          this.currentSession.inputKey(payload);
        }
        return '';
      case 'login':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            password?: string;
            os_username?: string;
            os_password?: string;
            remember?: boolean;
          };
          const password = String(payload.password ?? '').trim();
          const remember = payload.remember === true;
          const peerId = this.currentSession.getPeerId();
          this.store.set('remember', remember ? 'true' : 'false');
          if (remember && password && peerId) {
            this.setPeerOptionValue(peerId, 'password', password);
          }
          this.currentSession.login({
            password,
            osUsername: payload.os_username ?? '',
            osPassword: payload.os_password ?? '',
            remember
          });
        }
        return '';
      case 'send_2fa':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as { code?: string };
          if (payload.code) {
            this.currentSession.sendTwoFactor(payload.code);
          }
        }
        return '';
      case 'input_os_password':
        if (this.currentSession && typeof arg0 === 'string') {
          this.currentSession.login({
            password: '',
            osPassword: arg0
          });
        }
        return '';
      case 'send_chat':
        if (this.currentSession && typeof arg0 === 'string') {
          this.currentSession.sendChat(arg0);
        }
        return '';
      case 'toggle_privacy_mode':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            impl_key?: string;
            on?: boolean;
          };
          this.currentSession.togglePrivacyMode(
            String(payload.impl_key ?? ''),
            Boolean(payload.on)
          );
          const enabled = Boolean(payload.on);
          this.store.set('option:toggle:privacy-mode', enabled.toString());
          if (enabled) {
            const implKey = String(payload.impl_key ?? '');
            const fallback =
              this.store.get('option:session:privacy-mode-impl-key') ||
              'privacy_mode_impl_mag';
            this.store.set(
              'option:session:privacy-mode-impl-key',
              implKey || fallback
            );
          } else {
            this.store.set('option:session:privacy-mode-impl-key', '');
          }
        }
        return '';
      case 'toggle_virtual_display':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as { index?: number; on?: boolean };
          this.currentSession.toggleVirtualDisplay(
            Number(payload.index ?? 0),
            Boolean(payload.on)
          );
        }
        return '';
      case 'lock_screen':
        this.currentSession?.lockScreen();
        return '';
      case 'ctrl_alt_del':
        this.currentSession?.ctrlAltDel();
        return '';
      case 'switch_display':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as { value?: number[] };
          const displays = Array.isArray(payload.value) ? payload.value : [];
          this.currentSession.switchDisplay(displays);
        }
        return '';
      case 'change_resolution':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            display?: number;
            width?: number;
            height?: number;
          };
          this.currentSession.changeResolution(
            Number(payload.display ?? 0),
            Number(payload.width ?? 0),
            Number(payload.height ?? 0)
          );
        }
        return '';
      case 'selected_sid':
        if (this.currentSession) {
          const sid = Number(arg0 ?? 0);
          this.currentSession.selectSession(sid);
        }
        return '';
      case 'image_quality':
        if (typeof arg0 === 'string') {
          const quality = this.normalizeImageQualityValue(arg0);
          this.setScopedOption('option:session', 'image_quality', quality);
          this.currentSession?.setImageQuality(
            quality,
            this.getCustomImageQualityValue(),
            this.getCustomFpsValue()
          );
        }
        return '';
      case 'custom_image_quality':
        if (arg0 !== undefined && arg0 !== null) {
          const parsed = Number(arg0);
          const value =
            Number.isFinite(parsed) && parsed > 0
              ? Math.round(parsed)
              : this.getCustomImageQualityValue();
          this.setScopedOption('option:session', 'custom_image_quality', value);
          const fps = this.getCustomFpsValue();
          this.currentSession?.setCustomImageQuality(value, fps);
          if (this.resolveImageQualityPreference() === 'custom') {
            this.currentSession?.setImageQuality('custom', value, fps);
          }
        }
        return '';
      case 'custom-fps':
        if (arg0 !== undefined && arg0 !== null) {
          const parsed = Number(arg0);
          const fps =
            Number.isFinite(parsed) && parsed > 0
              ? Math.round(parsed)
              : this.getCustomFpsValue();
          this.setScopedOption('option:session', 'custom-fps', fps);
          this.currentSession?.setCustomFps(fps);
        }
        return '';
      case 'change_prefer_codec':
        if (this.currentSession) {
          const rawPreference = this.store.get('option:session:codec-preference', 'auto');
          const preference = this.normalizeCodecPreference(rawPreference);
          const preferI444 =
            this.store.get('option:toggle:i444', 'false') === 'true';
          void this.currentSession.changePreferCodec(preference, preferI444);
        }
        return '';
      case 'restart':
        this.currentSession?.restartRemote();
        return '';
      case 'elevate_direct':
        this.currentSession?.elevateDirect();
        return '';
      case 'elevate_with_logon':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as { username?: string; password?: string };
          this.currentSession.elevateWithLogon(
            String(payload.username ?? ''),
            String(payload.password ?? '')
          );
        }
        return '';
      case 'open_terminal':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            terminal_id?: number;
            rows?: number;
            cols?: number;
          };
          this.currentSession.openTerminal(
            Number(payload.terminal_id ?? 0),
            Number(payload.rows ?? 0),
            Number(payload.cols ?? 0)
          );
        }
        return '';
      case 'send_terminal_input':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as { terminal_id?: number; data?: string };
          this.currentSession.sendTerminalInput(
            Number(payload.terminal_id ?? 0),
            String(payload.data ?? '')
          );
        }
        return '';
      case 'resize_terminal':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            terminal_id?: number;
            rows?: number;
            cols?: number;
          };
          this.currentSession.resizeTerminal(
            Number(payload.terminal_id ?? 0),
            Number(payload.rows ?? 0),
            Number(payload.cols ?? 0)
          );
        }
        return '';
      case 'close_terminal':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as { terminal_id?: number };
          this.currentSession.closeTerminal(Number(payload.terminal_id ?? 0));
        }
        return '';
      case 'send_files':
        this.handleSendFiles(arg0);
        return '';
      case 'send_local_files':
        this.handleSendLocalFiles(arg0);
        return '';
      case 'register_drop_files':
        void this.handleRegisterDropFiles(arg0);
        return '';
      case 'select_files':
        void this.handleSelectFiles(Boolean(arg0));
        return '';
      case 'create_dir':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            id?: number;
            path?: string;
            is_remote?: boolean;
          };
          if (payload.is_remote) {
            this.currentSession.createDir(
              Number(payload.id ?? 0),
              String(payload.path ?? '')
            );
          } else {
            this.emitJobError(payload.id, 'one-way-file-transfer-tip');
          }
        }
        return '';
      case 'remove_file':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            id?: number;
            path?: string;
            file_num?: number;
            is_remote?: boolean;
          };
          if (payload.is_remote) {
            this.currentSession.removeFile(
              Number(payload.id ?? 0),
              String(payload.path ?? ''),
              Number(payload.file_num ?? 0)
            );
          } else {
            this.emitJobError(payload.id, 'one-way-file-transfer-tip');
          }
        }
        return '';
      case 'read_dir_to_remove_recursive':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            id?: number;
            path?: string;
            is_remote?: boolean;
            show_hidden?: boolean;
          };
          if (payload.is_remote) {
            this.currentSession.readAllFiles(
              Number(payload.id ?? 0),
              String(payload.path ?? ''),
              Boolean(payload.show_hidden)
            );
          } else {
            this.emitJobError(payload.id, 'one-way-file-transfer-tip');
          }
        }
        return '';
      case 'remove_all_empty_dirs':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            id?: number;
            path?: string;
            is_remote?: boolean;
          };
          if (payload.is_remote) {
            this.currentSession.removeDir(
              Number(payload.id ?? 0),
              String(payload.path ?? ''),
              true
            );
          } else {
            this.emitJobError(payload.id, 'one-way-file-transfer-tip');
          }
        }
        return '';
      case 'cancel_job':
        if (this.currentSession) {
          this.currentSession.cancelJob(Number(arg0 ?? 0));
        }
        return '';
      case 'confirm_override_file':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            id?: number;
            file_num?: number;
            need_override?: boolean;
          };
          this.currentSession.confirmOverrideFile(
            Number(payload.id ?? 0),
            Number(payload.file_num ?? 0),
            Boolean(payload.need_override)
          );
        }
        return '';
      case 'rename_file':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            id?: number;
            path?: string;
            new_name?: string;
            is_remote?: boolean;
          };
          if (payload.is_remote) {
            this.currentSession.renameFile(
              Number(payload.id ?? 0),
              String(payload.path ?? ''),
              String(payload.new_name ?? '')
            );
          } else {
            this.emitJobError(payload.id, 'one-way-file-transfer-tip');
          }
        }
        return '';
      case 'send_note':
        if (typeof arg0 === 'string') {
          this.store.set('last_audit_note', arg0);
        }
        return '';
      case 'load_ab':
        if (typeof window.onLoadAbFinished === 'function') {
          window.onLoadAbFinished(this.store.get('address_book', '[]'));
        }
        return '';
      case 'load_group':
        if (typeof window.onLoadGroupFinished === 'function') {
          window.onLoadGroupFinished(this.store.get('groups', '[]'));
        }
        return '';
      case 'load_recent_peers':
        this.emitPeerLoadEvent('load_recent_peers', this.getRecentPeers());
        return '';
      case 'load_fav_peers':
        this.emitPeerLoadEvent('load_fav_peers', this.getFavoritePeers());
        return '';
      case 'load_lan_peers':
        this.emitPeerLoadEvent('load_lan_peers', this.getLanPeers());
        return '';
      case 'discover':
        // Browser runtime cannot perform native LAN discovery; reuse cached LAN peers.
        this.emitPeerLoadEvent('load_lan_peers', this.getLanPeers());
        return '';
      case 'query_onlines':
        this.handleQueryOnlines(arg0);
        return '';
      case 'check_connect_status':
        this.startConnectStatusProbe();
        return '';
      case 'account_auth':
        this.startAccountAuth(arg0);
        return '';
      case 'account_auth_cancel':
        this.cancelAccountAuth();
        return '';
      case 'read_remote_dir':
        if (this.currentSession && typeof arg0 === 'string') {
          const payload = this.safeJson(arg0) as {
            path?: string;
            include_hidden?: boolean;
          };
          this.currentSession.readRemoteDir(
            payload.path ?? '',
            Boolean(payload.include_hidden)
          );
        }
        return '';
      default:
        if (arg1 !== undefined) {
          this.store.set(`${name}:${String(arg0)}`, arg1);
        } else if (arg0 !== undefined) {
          this.store.set(name, arg0);
        }
        return '';
    }
  }

  getByName(name: string, arg0?: unknown): string {
    switch (name) {
      case 'app-name':
        return this.config.appName;
      case 'version':
        return this.config.version;
      case 'build_date':
        return this.config.buildDate;
      case 'fingerprint':
        return this.ensureFingerprint();
      case 'api_server':
        return this.resolveApiServer();
      case 'is_using_public_server':
        return this.isUsingPublicServer() ? 'true' : 'false';
      case 'platform':
        return 'WebDesktop';
      case 'local_os':
        return detectOs();
      case 'screen_info':
        return screenInfo();
      case 'remember':
        return this.store.get('remember', 'false');
      case 'my_id':
        return this.store.get('my_id', this.config.profile.id ?? '');
      case 'my_name':
        return this.store.get('my_name', this.config.profile.name ?? 'Web User');
      case 'uuid':
        return this.store.ensure('uuid', generateUuid);
      case 'envvar':
        if (typeof arg0 === 'string') {
          return this.config.env[arg0] ?? this.store.get(`envvar:${arg0}`, '');
        }
        return '';
      case 'option:toggle':
        return this.getToggleOption(String(arg0 ?? '')) ? 'true' : 'false';
      case 'option:session':
      case 'option:local':
      case 'option:peer':
      case 'option:flutter:peer':
      case 'option:flutter:local':
      case 'option:user:default':
        if (name === 'option:peer') {
          return this.getPeerOptionValueFromArg(arg0);
        }
        return this.getScopedOption(name, String(arg0 ?? ''));
      case 'option':
        return this.getOption(String(arg0 ?? ''));
      case 'common':
        return this.store.get(`common:${String(arg0 ?? '')}`, '');
      case 'options':
        return JSON.stringify(this.getOptionsSnapshot());
      case 'fav':
        return this.store.get('fav', '[]');
      case 'load_recent_peers':
      case 'load_recent_peers_sync':
        return JSON.stringify(this.getRecentPeers());
      case 'load_fav_peers':
        return JSON.stringify(this.getFavoritePeers());
      case 'load_lan_peers':
      case 'load_lan_peers_sync':
        return JSON.stringify(this.getLanPeers());
      case 'load_recent_peers_for_ab':
        return this.getRecentPeersForAb(arg0);
      case 'load_ab':
        return this.store.get('address_book', '[]');
      case 'load_group':
        return this.store.get('groups', '[]');
      case 'langs':
        return typeof this.config.langs === 'string'
          ? this.config.langs
          : JSON.stringify(this.config.langs ?? []);
      case 'alternative_codecs':
        return this.computeAlternativeCodecs();
      case 'get_version_number':
        return String(this.getVersionNumber(String(arg0 ?? '')));
      case 'translate':
        return this.handleTranslate(arg0);
      case 'get_conn_status':
        return this.store.get('service_status', 'disconnected');
      case 'main_display':
        return this.store.get('main_display', '0');
      case 'custom_image_quality':
        return String(this.getCustomImageQualityValue());
      case 'image_quality':
        return this.resolveImageQualityPreference();
      case 'peer_has_password':
        if (typeof arg0 === 'string') {
          const peerId = String(arg0 ?? '').trim();
          if (!peerId) {
            return 'false';
          }
          return this.getPeerOptionValue(peerId, 'password').trim() ? 'true' : 'false';
        }
        return 'false';
      case 'peer_exists':
        if (typeof arg0 === 'string') {
          return this.findPeerById(arg0) ? 'true' : 'false';
        }
        return 'false';
      case 'peer_sync':
        if (typeof arg0 === 'string') {
          return this.getPeerSync(arg0);
        }
        return '{}';
      case 'new_stored_peers': {
        const value = this.store.get('new_stored_peers', '[]');
        this.store.set('new_stored_peers', '[]');
        return value;
      }
      case 'test_if_valid_server':
        return this.testIfValidServer(String(arg0 ?? ''));
      case 'enable_trusted_devices':
        return this.store.get('enable_trusted_devices', '');
      case 'conn_session_id':
        return this.store.get('conn_session_id', '');
      case 'last_audit_note':
        return this.store.get('last_audit_note', '');
      case 'audit_guid':
        return this.store.get('audit_guid', '');
      case 'audit_server':
        if (typeof arg0 === 'string') {
          return this.store.get(`audit_server:${arg0}`, '');
        }
        return '';
      case 'account_auth_result':
        return this.store.get('account_auth_result', '');
      default:
        if (arg0 !== undefined) {
          return this.store.get(`${name}:${String(arg0)}`, '');
        }
        return this.store.get(name, '');
    }
  }

  private bindEventSinks(): void {
    this.events.onEmit((event) => {
      switch (event.name) {
        case 'conn_status':
          if (event.status !== undefined) {
            const status = String(event.status);
            this.store.set('session_conn_status', status);
            if (status === 'connecting') {
              this.setServiceStatus('connecting');
            } else if (status === 'connected') {
              this.setServiceStatus('connected');
            } else if (status === 'error') {
              this.setServiceStatus('error');
            } else if (status === 'closed') {
              this.setServiceStatus('disconnected');
            }
          }
          break;
        case 'peer_info':
          if (event.current_display !== undefined) {
            this.store.set('main_display', String(event.current_display));
          }
          this.updateCurrentPeerMetadataFromPeerInfo(event);
          break;
        case 'switch_display':
          if (event.display !== undefined) {
            this.store.set('main_display', String(event.display));
          }
          break;
        case 'enable_trusted_devices': {
          const raw = String(event.value ?? '').toLowerCase();
          const enabled = raw === 'true' || raw === '1' || raw === 'y';
          this.store.set('enable_trusted_devices', enabled ? 'Y' : '');
          break;
        }
        case 'update_block_input_state': {
          const on = String(event.input_state ?? '') === 'on';
          this.store.set('option:toggle:block-input', on.toString());
          break;
        }
        case 'update_privacy_mode': {
          let on: boolean | null = null;
          const mode = String(event.privacy_mode ?? '')
            .trim()
            .toLowerCase();
          if (mode === 'on' || mode === 'true' || mode === '1' || mode === 'y') {
            on = true;
          } else if (
            mode === 'off' ||
            mode === 'false' ||
            mode === '0' ||
            mode === 'n'
          ) {
            on = false;
          } else {
            const state = Number(event.privacy_mode_state);
            if (state === 4) {
              on = true;
            } else if (
              state === 3 ||
              state === 5 ||
              state === 6 ||
              state === 7 ||
              state === 8 ||
              state === 9 ||
              state === 11
            ) {
              on = false;
            }
          }
          if (on !== null) {
            this.store.set('option:toggle:privacy-mode', on.toString());
            if (on) {
              const implKey = String(event.impl_key ?? '').trim();
              const fallback =
                this.store.get('option:session:privacy-mode-impl-key') ||
                'privacy_mode_impl_mag';
              this.store.set(
                'option:session:privacy-mode-impl-key',
                implKey || fallback
              );
            } else {
              this.store.set('option:session:privacy-mode-impl-key', '');
            }
          }
          break;
        }
        case 'sync_peer_option':
          if (typeof event.k === 'string') {
            const v = event.v === true || event.v === 'true';
            this.store.set(`option:toggle:${event.k}`, v.toString());
          }
          break;
        default:
          break;
      }
    });
    this.events.bindGlobalSink((payload) => {
      if (typeof window.onGlobalEvent === 'function') {
        window.onGlobalEvent(payload);
      }
    });
    this.events.bindRegisteredSink((payload) => {
      if (typeof window.onRegisteredEvent === 'function') {
        window.onRegisteredEvent(payload);
      }
    });
  }

  private setOptionPayload(prefix: string, arg0?: unknown, arg1?: unknown): void {
    if (arg1 !== undefined) {
      if (arg0 !== undefined) {
        this.setScopedOption(prefix, String(arg0), arg1);
      }
      return;
    }
    if (typeof arg0 !== 'string') {
      return;
    }
    try {
      const parsed = JSON.parse(arg0) as OptionPayload;
      if (!parsed || typeof parsed.name !== 'string') {
        return;
      }
      this.setScopedOption(prefix, parsed.name, parsed.value ?? '');
    } catch {
      // Ignore invalid JSON.
    }
  }

  private setPeerOptionPayload(arg0?: unknown): void {
    const payload = this.parsePeerOptionPayload(arg0);
    if (!payload) {
      return;
    }
    const value = payload.value ?? '';
    this.setPeerOptionValue(payload.id, payload.name, value);
  }

  private getPeerOptionValueFromArg(arg0?: unknown): string {
    const payload = this.parsePeerOptionPayload(arg0);
    if (!payload) {
      return '';
    }
    return this.getPeerOptionValue(payload.id, payload.name);
  }

  private parsePeerOptionPayload(
    input?: unknown
  ): { id: string; name: string; value?: string } | null {
    if (!input) {
      return null;
    }
    let payload: Record<string, unknown> | null = null;
    if (typeof input === 'string') {
      const trimmed = input.trim();
      if (!trimmed) {
        return null;
      }
      if (trimmed.startsWith('{')) {
        payload = this.safeJson(trimmed) as Record<string, unknown>;
      } else {
        return null;
      }
    } else if (typeof input === 'object') {
      payload = input as Record<string, unknown>;
    }
    if (!payload) {
      return null;
    }
    const id = String(payload.id ?? '').trim();
    const name = String(payload.name ?? '').trim();
    if (!id || !name) {
      return null;
    }
    return {
      id,
      name,
      value:
        payload.value !== undefined && payload.value !== null
          ? String(payload.value)
          : undefined
    };
  }

  private peerOptionKey(id: string): string {
    return `peer_option:${id}`;
  }

  private getLocalSecretSeed(): string {
    return this.store.ensure('uuid', generateUuid);
  }

  private encryptLocalPasswordValue(value: string): string {
    const normalized = String(value ?? '');
    if (!normalized) {
      return '';
    }
    try {
      return encryptLocalSecret(normalized, this.getLocalSecretSeed());
    } catch (err) {
      this.logger.warn('Failed to encrypt password for local storage', err);
      return '';
    }
  }

  private decryptLocalPasswordValue(value: string): string {
    const decoded = decryptLocalSecret(String(value ?? ''), this.getLocalSecretSeed());
    return decoded ?? '';
  }

  private decodePeerPasswordOption(id: string, value: string): string {
    return this.decryptLocalPasswordValue(value);
  }

  private getPeerOptions(id: string): Record<string, string> {
    if (!id) {
      return {};
    }
    return this.store.getJson<Record<string, string>>(this.peerOptionKey(id), {});
  }

  private getPeerOptionValue(id: string, name: string): string {
    if (!id || !name) {
      return '';
    }
    const options = this.getPeerOptions(id);
    const value = options[name] ?? '';
    if (name === 'password') {
      return this.decodePeerPasswordOption(id, value);
    }
    return value;
  }

  private setPeerOptionValue(id: string, name: string, value: string): void {
    if (!id || !name) {
      return;
    }
    const options = this.getPeerOptions(id);
    const normalized = String(value ?? '');
    const stored =
      name === 'password'
        ? this.encryptLocalPasswordValue(normalized)
        : normalized;
    if (stored) {
      options[name] = stored;
    } else {
      delete options[name];
    }
    this.store.setJson(this.peerOptionKey(id), options);
  }

  private isForceAlwaysRelayEnabled(id: string): boolean {
    return this.getPeerOptionValue(id, 'force-always-relay') === 'Y';
  }

  private setScopedOption(prefix: string, key: string, value: unknown): void {
    if (prefix === 'option') {
      this.setOptionValue(key, value);
      return;
    }
    let normalized = String(value ?? '');
    if (prefix === 'option:session' && key === 'codec-preference') {
      normalized = this.normalizeCodecPreference(normalized);
    }
    this.store.set(`${prefix}:${key}`, normalized);
    if (
      prefix === 'option:local' &&
      key === 'input-source' &&
      normalized !== 'Input source 1'
    ) {
      this.inputSource1PointerInside = false;
      this.releaseInputSource1PressedKeys();
    }
  }

  private setOptionValue(key: string, value: unknown): void {
    const normalized = String(value ?? '');
    this.store.set(`option:${key}`, normalized);
    const options = this.store.getJson<Record<string, string>>('options', {});
    if (normalized) {
      options[key] = normalized;
    } else {
      delete options[key];
    }
    this.store.setJson('options', options);
    if (
      key === 'custom-rendezvous-server' ||
      key === 'relay-server' ||
      key === 'api-server'
    ) {
      this.scheduleConnectStatusProbe();
    }
  }

  private setOptionsPayload(arg0?: unknown): void {
    if (typeof arg0 === 'string') {
      const raw = arg0.trim();
      if (!raw) {
        this.replaceOptionsFromObject({});
        return;
      }
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        this.replaceOptionsFromObject(parsed);
        return;
      } catch {
        this.store.set('options', arg0);
        return;
      }
    }
    if (arg0 && typeof arg0 === 'object') {
      this.replaceOptionsFromObject(arg0 as Record<string, unknown>);
    }
  }

  private setCommonPayload(arg0?: unknown): void {
    if (typeof arg0 !== 'string') {
      return;
    }
    try {
      const parsed = JSON.parse(arg0) as { key?: unknown; value?: unknown };
      if (typeof parsed.key !== 'string') {
        return;
      }
      this.store.set(`common:${parsed.key}`, String(parsed.value ?? ''));
    } catch {
      // Ignore invalid payloads.
    }
  }

  private replaceOptionsFromObject(parsed: Record<string, unknown>): void {
    const current = this.store.getJson<Record<string, string>>('options', {});
    for (const key of Object.keys(current)) {
      if (!(key in parsed)) {
        this.setOptionValue(key, '');
      }
    }
    for (const [key, value] of Object.entries(parsed)) {
      this.setOptionValue(key, value ?? '');
    }
  }

  private getScopedOption(prefix: string, key: string): string {
    const scopedKey = `${prefix}:${key}`;
    const stored = this.store.get(scopedKey, '');
    if (stored) {
      return stored;
    }
    if (prefix === 'option:local') {
      return this.localOptionDefaults.get(key) ?? '';
    }
    if (prefix === 'option:session') {
      return (
        this.userDefaultOptionDefaults.get(key) ??
        this.optionDefaults.get(key) ??
        ''
      );
    }
    if (prefix === 'option:flutter:local') {
      return this.flutterLocalOptionDefaults.get(key) ?? '';
    }
    if (prefix === 'option:user:default') {
      return this.userDefaultOptionDefaults.get(key) ?? '';
    }
    return '';
  }

  private normalizeImageQualityValue(raw: unknown): string {
    const normalized = String(raw ?? '')
      .trim()
      .toLowerCase();
    switch (normalized) {
      case 'best':
      case 'balanced':
      case 'low':
      case 'custom':
        return normalized;
      default:
        return 'balanced';
    }
  }

  private normalizeCodecPreference(raw: unknown): string {
    const normalized = String(raw ?? '')
      .trim()
      .toLowerCase();
    switch (normalized) {
      case 'auto':
      case 'vp8':
      case 'vp9':
      case 'av1':
      case 'h264':
      case 'h265':
        return normalized;
      default:
        return 'auto';
    }
  }

  private resolveImageQualityPreference(): string {
    return this.normalizeImageQualityValue(
      this.getScopedOption('option:session', 'image_quality')
    );
  }

  private getCustomImageQualityValue(): number {
    const scoped = Number(
      this.getScopedOption('option:session', 'custom_image_quality')
    );
    if (Number.isFinite(scoped) && scoped > 0) {
      return Math.round(scoped);
    }
    return 100;
  }

  private getCustomFpsValue(): number {
    const scoped = Number(this.getScopedOption('option:session', 'custom-fps'));
    if (Number.isFinite(scoped) && scoped > 0) {
      return Math.round(scoped);
    }
    return 60;
  }

  private getOptionsSnapshot(): Record<string, string> {
    const merged: Record<string, string> = {};
    for (const [key, value] of this.optionDefaults.entries()) {
      if (value) {
        merged[key] = value;
      }
    }
    const stored = this.store.getJson<Record<string, string>>('options', {});
    for (const [key, value] of Object.entries(stored)) {
      if (value) {
        merged[key] = value;
      } else {
        delete merged[key];
      }
    }
    const coreKeys = ['custom-rendezvous-server', 'relay-server', 'api-server', 'key'];
    for (const key of coreKeys) {
      const value = this.getOption(key);
      if (value) {
        merged[key] = value;
      } else {
        delete merged[key];
      }
    }
    return merged;
  }

  private toggleOption(optionName: string): string {
    if (!optionName) {
      return 'false';
    }
    let normalized = optionName;
    let forced: boolean | null = null;
    if (optionName === 'unblock-input') {
      normalized = 'block-input';
      forced = false;
    } else if (optionName === 'block-input') {
      forced = true;
    }
    const key = `option:toggle:${normalized}`;
    if (normalized === 'i444' && !this.supportsI444Preference()) {
      this.store.set(key, 'false');
      return 'false';
    }
    const current = this.getToggleOption(normalized);
    const next = forced ?? !current;
    this.store.set(key, next.toString());
    this.applyToggleOption(normalized, next);
    return next.toString();
  }

  private applyToggleOption(name: string, value: boolean): void {
    if (name === 'view-only' || name === 'show-my-cursor') {
      this.events.emit({
        name: 'sync_peer_option',
        k: name,
        v: value
      });
    }
    if (name === 'view-only') {
      this.applyViewOnlyToggle(value);
      return;
    }
    if (name === 'privacy-mode') {
      // Native clients use `togglePrivacyMode` misc message rather than
      // generic option sync for privacy mode.
      const implKey =
        this.store.get('option:session:privacy-mode-impl-key') ||
        'privacy_mode_impl_mag';
      if (value) {
        this.store.set('option:session:privacy-mode-impl-key', implKey);
      } else {
        this.store.set('option:session:privacy-mode-impl-key', '');
      }
      this.currentSession?.togglePrivacyMode(implKey, value);
      // Keep option sync for compatibility with older peers that still
      // observe the legacy privacyMode option path.
      this.currentSession?.sendOption({
        privacyMode: this.boolOption(value)
      });
      return;
    }
    if (!this.currentSession) {
      return;
    }
    const field = this.toggleOptionField(name);
    if (!field) {
      return;
    }
    this.currentSession.sendOption({ [field]: this.boolOption(value) });
  }

  private toggleOptionField(name: string): string | null {
    switch (name) {
      case 'lock-after-session-end':
        return 'lockAfterSessionEnd';
      case 'show-remote-cursor':
        return 'showRemoteCursor';
      case 'privacy-mode':
        return 'privacyMode';
      case 'block-input':
        return 'blockInput';
      case 'disable-audio':
        return 'disableAudio';
      case 'disable-clipboard':
        return 'disableClipboard';
      case 'enable-file-transfer':
      case 'enable-file-copy-paste':
        return 'enableFileTransfer';
      case 'disable-keyboard':
        return 'disableKeyboard';
      case 'disable-camera':
        return 'disableCamera';
      case 'follow-remote-cursor':
        return 'followRemoteCursor';
      case 'follow-remote-window':
        return 'followRemoteWindow';
      case 'terminal-persistent':
        return 'terminalPersistent';
      case 'show-my-cursor':
        return 'showMyCursor';
      default:
        return null;
    }
  }

  private boolOption(value: boolean): number {
    return value ? 2 : 1;
  }

  private getToggleOption(name: string): boolean {
    if (!name) {
      return false;
    }
    if (name === 'i444' && !this.supportsI444Preference()) {
      return false;
    }
    const stored = this.store.get(`option:toggle:${name}`, '');
    if (stored) {
      return stored === 'true';
    }

    // Follow native client behavior: toggle values fall back to user defaults
    // when session state does not have an explicit override yet.
    const defaultKeys = [name, name.replace(/-/g, '_')];
    for (const key of defaultKeys) {
      const value = this.getScopedOption('option:user:default', key);
      if (value) {
        return this.parseBoolOptionValue(value);
      }
    }
    return false;
  }

  private supportsI444Preference(): boolean {
    // Web decoder pipeline currently configures 4:2:0 codec profiles only.
    // Keep i444 disabled to avoid stream freezes when remote switches chroma profile.
    return false;
  }

  private parseBoolOptionValue(value: string): boolean {
    return this.parseBoolLike(value);
  }

  private parseBoolLike(value: unknown): boolean {
    if (typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'number') {
      return value !== 0;
    }
    const normalized = String(value ?? '')
      .trim()
      .toLowerCase();
    return (
      normalized === 'true' ||
      normalized === '1' ||
      normalized === 'y' ||
      normalized === 'yes' ||
      normalized === 'on'
    );
  }

  private applyViewOnlyToggle(enabled: boolean): void {
    if (!this.currentSession) {
      return;
    }
    const option: Record<string, unknown> = {};
    if (enabled) {
      option.disableKeyboard = this.boolOption(true);
      option.disableClipboard = this.boolOption(true);
      option.showRemoteCursor = this.boolOption(true);
      option.enableFileTransfer = this.boolOption(false);
      option.lockAfterSessionEnd = this.boolOption(false);
    } else {
      option.disableKeyboard = this.boolOption(false);
      option.disableClipboard = this.boolOption(
        this.getToggleOption('disable-clipboard')
      );
      option.showRemoteCursor = this.boolOption(
        this.getToggleOption('show-remote-cursor')
      );
      option.enableFileTransfer = this.boolOption(
        this.getToggleOption('enable-file-copy-paste')
      );
      option.lockAfterSessionEnd = this.boolOption(
        this.getToggleOption('lock-after-session-end')
      );
      if (this.getToggleOption('show-my-cursor')) {
        this.store.set('option:toggle:show-my-cursor', 'false');
        option.showMyCursor = this.boolOption(false);
        this.events.emit({
          name: 'sync_peer_option',
          k: 'show-my-cursor',
          v: false
        });
      }
    }
    this.currentSession.sendOption(option);
  }

  private applyLocalMouseOptions(payload: Record<string, unknown>): void {
    if (this.getToggleOption('swap-left-right-mouse')) {
      const button = String(payload.buttons ?? '')
        .trim()
        .toLowerCase();
      if (button === 'left' || button === '1') {
        payload.buttons = 'right';
      } else if (button === 'right' || button === '2') {
        payload.buttons = 'left';
      }
    }
    this.applyLocalModifierSwap(payload);
    if (
      payload.type === 'wheel' &&
      this.parseBoolOptionValue(
        this.getScopedOption('option:session', 'reverse_mouse_wheel')
      )
    ) {
      const raw = Number(payload.y ?? 0);
      if (Number.isFinite(raw) && raw !== 0) {
        payload.y = String(-raw);
      }
    }
  }

  private bindInputSource1Handlers(): void {
    window.addEventListener(
      'keydown',
      (event) => this.handleInputSource1KeyDown(event),
      true
    );
    window.addEventListener(
      'keyup',
      (event) => this.handleInputSource1KeyUp(event),
      true
    );
    window.addEventListener('blur', () => this.releaseInputSource1PressedKeys());
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.releaseInputSource1PressedKeys();
      }
    });
  }

  private handleInputSource1KeyDown(event: KeyboardEvent): void {
    if (!this.shouldCaptureInputSource1Key(event)) {
      return;
    }
    const keyName = this.normalizeInputSource1Key(event.key);
    if (!keyName) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (keyName.length === 1) {
      this.sendInputSource1Key({
        name: keyName,
        press: true,
        alt: event.altKey,
        ctrl: event.ctrlKey,
        shift: event.shiftKey,
        command: event.metaKey
      });
      return;
    }
    const keyId = this.inputSource1KeyId(event, keyName);
    if (event.repeat && this.inputSource1PressedKeys.has(keyId)) {
      return;
    }
    this.inputSource1PressedKeys.set(keyId, keyName);
    this.sendInputSource1Key({
      name: keyName,
      down: true,
      alt: event.altKey,
      ctrl: event.ctrlKey,
      shift: event.shiftKey,
      command: event.metaKey
    });
  }

  private handleInputSource1KeyUp(event: KeyboardEvent): void {
    if (!this.currentSession || !this.isInputSource1Enabled()) {
      return;
    }
    const keyName = this.normalizeInputSource1Key(event.key);
    if (!keyName) {
      return;
    }
    const keyId = this.inputSource1KeyId(event, keyName);
    if (!this.inputSource1PressedKeys.has(keyId)) {
      return;
    }
    this.inputSource1PressedKeys.delete(keyId);
    if (
      !this.inputSource1PointerInside ||
      this.isEditableTarget(event.target) ||
      this.getToggleOption('view-only')
    ) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    this.sendInputSource1Key({
      name: keyName,
      down: false,
      alt: event.altKey,
      ctrl: event.ctrlKey,
      shift: event.shiftKey,
      command: event.metaKey
    });
  }

  private shouldCaptureInputSource1Key(event: KeyboardEvent): boolean {
    return (
      !!this.currentSession &&
      this.inputSource1PointerInside &&
      this.isInputSource1Enabled() &&
      !this.getToggleOption('view-only') &&
      !event.defaultPrevented &&
      !this.isEditableTarget(event.target)
    );
  }

  private isInputSource1Enabled(): boolean {
    return this.getScopedOption('option:local', 'input-source') === 'Input source 1';
  }

  private isEditableTarget(target: EventTarget | null): boolean {
    if (!(target instanceof HTMLElement)) {
      return false;
    }
    const tag = target.tagName.toLowerCase();
    return (
      target.isContentEditable ||
      tag === 'input' ||
      tag === 'textarea' ||
      tag === 'select'
    );
  }

  private normalizeInputSource1Key(rawKey: unknown): string {
    const key = String(rawKey ?? '');
    if (!key || key === 'Unidentified' || key === 'Dead' || key === 'Process') {
      return '';
    }
    if (key === 'Esc') {
      return 'Escape';
    }
    if (key === 'OS') {
      return 'Meta';
    }
    if (key === 'Spacebar') {
      return ' ';
    }
    if (key === 'AltGraph') {
      return 'Alt';
    }
    return key;
  }

  private inputSource1KeyId(event: KeyboardEvent, keyName: string): string {
    const code = String(event.code ?? '');
    return code || keyName.toLowerCase();
  }

  private sendInputSource1Key(payload: Record<string, unknown>): void {
    if (!this.currentSession) {
      return;
    }
    this.applyLocalKeyOptions(payload);
    this.currentSession.inputKey(payload);
  }

  private releaseInputSource1PressedKeys(): void {
    if (!this.currentSession) {
      this.inputSource1PressedKeys.clear();
      return;
    }
    for (const keyName of this.inputSource1PressedKeys.values()) {
      this.currentSession.inputKey({
        name: keyName,
        down: false
      });
    }
    this.inputSource1PressedKeys.clear();
  }

  private applyLocalKeyOptions(payload: Record<string, unknown>): void {
    if (!this.getToggleOption('allow_swap_key')) {
      return;
    }
    this.applyLocalModifierSwap(payload);
    const name = String(payload.name ?? '')
      .trim()
      .toLowerCase();
    if (name === 'control' || name === 'ctrl' || name === 'rcontrol') {
      payload.name = 'Meta';
    } else if (
      name === 'meta' ||
      name === 'command' ||
      name === 'os' ||
      name === 'rwin'
    ) {
      payload.name = 'Control';
    }
  }

  private applyLocalModifierSwap(payload: Record<string, unknown>): void {
    if (!this.getToggleOption('allow_swap_key')) {
      return;
    }
    const hasCtrl = payload.ctrl !== undefined;
    const hasCommand = payload.command !== undefined;
    if (!hasCtrl && !hasCommand) {
      return;
    }
    const ctrl = this.parseBoolLike(payload.ctrl);
    const command = this.parseBoolLike(payload.command);
    payload.ctrl = command;
    payload.command = ctrl;
  }

  private applyLocalFlutterKeyOptions(payload: Record<string, unknown>): void {
    if (!this.getToggleOption('allow_swap_key')) {
      return;
    }
    const rawUsbHid = Number(payload.usb_hid ?? 0);
    if (!Number.isFinite(rawUsbHid)) {
      return;
    }
    switch (rawUsbHid) {
      case 0xe0:
        payload.usb_hid = 0xe3;
        break;
      case 0xe3:
        payload.usb_hid = 0xe0;
        break;
      case 0xe4:
        payload.usb_hid = 0xe7;
        break;
      case 0xe7:
        payload.usb_hid = 0xe4;
        break;
      default:
        break;
    }
  }

  private handleFlutterRawKeyEvent(payload: Record<string, unknown>): void {
    if (!this.currentSession) {
      return;
    }
    const name = this.normalizeFlutterRawKeyName(payload.name);
    if (!name) {
      return;
    }
    const keyPayload: Record<string, unknown> = {
      name,
      down: this.parseBoolLike(payload.down_or_up ?? payload.downOrUp)
    };
    this.applyLocalKeyOptions(keyPayload);
    this.currentSession.inputKey(keyPayload);
  }

  private normalizeFlutterRawKeyName(rawName: unknown): string {
    const key = String(rawName ?? '').trim();
    if (!key) {
      return '';
    }
    const directMap: Record<string, string> = {
      RControl: 'Control',
      VK_CONTROL: 'Control',
      RShift: 'Shift',
      VK_SHIFT: 'Shift',
      RAlt: 'Alt',
      VK_MENU: 'Alt',
      Meta: 'Meta',
      OS: 'Meta',
      VK_SPACE: ' ',
      VK_TAB: 'Tab',
      VK_ENTER: 'Enter',
      VK_ESCAPE: 'Escape',
      VK_BACK: 'Backspace',
      VK_DELETE: 'Delete',
      VK_CAPITAL: 'CapsLock',
      VK_PAUSE: 'Pause',
      VK_UP: 'ArrowUp',
      VK_DOWN: 'ArrowDown',
      VK_LEFT: 'ArrowLeft',
      VK_RIGHT: 'ArrowRight',
      VK_HOME: 'Home',
      VK_END: 'End',
      VK_PRIOR: 'PageUp',
      VK_NEXT: 'PageDown',
      VK_INSERT: 'Insert',
      VK_MINUS: '-',
      VK_PLUS: '=',
      VK_COMMA: ',',
      VK_SLASH: '/',
      VK_QUOTE: "'",
      VK_SEMICOLON: ';',
      VK_LBRACKET: '[',
      VK_RBRACKET: ']',
      VK_BACKSLASH: '\\',
      VK_MULTIPLY: '*',
      VK_ADD: '+',
      VK_SUBTRACT: '-',
      VK_DIVIDE: '/',
      VK_DECIMAL: '.'
    };
    if (directMap[key]) {
      return directMap[key];
    }
    if (/^VK_F\d{1,2}$/.test(key)) {
      return key.substring(3);
    }
    if (/^VK_[A-Z]$/.test(key)) {
      return key.substring(3).toLowerCase();
    }
    if (/^VK_[0-9]$/.test(key)) {
      return key.substring(3);
    }
    if (/^VK_NUMPAD[0-9]$/.test(key)) {
      return key.substring('VK_NUMPAD'.length);
    }
    return key;
  }

  private handlePointerPayload(payload: Record<string, unknown>): void {
    if (!this.currentSession) {
      return;
    }
    const kind = String(payload.k ?? '')
      .trim()
      .toLowerCase();
    if (kind !== 'touch') {
      return;
    }
    const body = payload.v as Record<string, unknown> | undefined;
    if (!body) {
      return;
    }
    const type = String(body.t ?? '')
      .trim()
      .toLowerCase();
    if (type === 'pan_update') {
      const value = body.v as Record<string, unknown> | undefined;
      if (!value) {
        return;
      }
      const mousePayload: Record<string, unknown> = {
        type: 'trackpad',
        x: String(value.x ?? 0),
        y: String(value.y ?? 0)
      };
      this.applyLocalMouseOptions(mousePayload);
      this.currentSession.sendMouse(mousePayload);
      return;
    }
    if (type === 'scale') {
      const rawScale = Number(body.v ?? 0);
      if (!Number.isFinite(rawScale) || rawScale === 0) {
        return;
      }
      const mousePayload: Record<string, unknown> = {
        type: 'wheel',
        x: '0',
        y: rawScale > 0 ? '1' : '-1'
      };
      this.applyLocalMouseOptions(mousePayload);
      this.currentSession.sendMouse(mousePayload);
    }
  }

  private handleSendFiles(arg0?: unknown): void {
    if (!this.currentSession || typeof arg0 !== 'string') {
      return;
    }
    const payload = this.safeJson(arg0) as {
      id?: number;
      path?: string;
      include_hidden?: boolean;
      is_remote?: boolean;
      file_num?: number;
    };
    if (!payload.is_remote) {
      this.emitJobError(payload.id, 'one-way-file-transfer-tip');
      return;
    }
    const path = String(payload.path ?? '');
    if (!path) {
      return;
    }
    this.currentSession.requestDownload(
      Number(payload.id ?? 0),
      path,
      Boolean(payload.include_hidden),
      Number(payload.file_num ?? 0)
    );
  }

  private handleSendLocalFiles(arg0?: unknown): void {
    if (!this.currentSession || typeof arg0 !== 'string') {
      return;
    }
    const payload = this.safeJson(arg0) as {
      id?: number;
      handle_index?: number;
      path?: string;
      to?: string;
    };
    const handleIndex = Number(payload.handle_index ?? 0);
    const files = this.fileHandles.get(handleIndex);
    if (!files || files.length === 0) {
      this.emitJobError(payload.id, 'file-not-found');
      return;
    }
    const desired = String(payload.path ?? '');
    const file =
      files.find((item) => {
        const relative = (item as File & { webkitRelativePath?: string })
          .webkitRelativePath;
        if (relative && relative.length > 0) {
          return relative === desired;
        }
        return item.name === desired;
      }) ?? files[0];
    if (!file) {
      this.emitJobError(payload.id, 'file-not-found');
      return;
    }
    const idx = files.indexOf(file);
    if (idx >= 0) {
      files.splice(idx, 1);
      if (files.length === 0) {
        this.fileHandles.delete(handleIndex);
      }
    }
    const remotePath =
      payload.to !== undefined && payload.to !== null && payload.to !== ''
        ? String(payload.to)
        : desired || file.name;
    this.currentSession.startUpload(Number(payload.id ?? 0), file, remotePath);
  }

  private async handleRegisterDropFiles(arg0?: unknown): Promise<void> {
    const payload =
      typeof arg0 === 'string'
        ? (this.safeJson(arg0) as { files?: DroppedFilePayload[] })
        : undefined;
    const descriptors = Array.isArray(payload?.files) ? payload.files : [];
    if (descriptors.length === 0) {
      return;
    }
    const files = await Promise.all(
      descriptors.map((file) => this.rehydrateDroppedFile(file))
    );
    const ready = files.filter((file): file is File => file !== null);
    if (ready.length === 0) {
      return;
    }
    const handleIndex = this.nextFileHandle++;
    this.fileHandles.set(handleIndex, ready);
    this.emitSelectedFiles(handleIndex, ready);
  }

  private async handleSelectFiles(isFolder: boolean): Promise<void> {
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    if (isFolder) {
      (input as HTMLInputElement & { webkitdirectory?: boolean }).webkitdirectory = true;
      input.setAttribute('webkitdirectory', '');
    }
    input.addEventListener(
      'change',
      () => {
        void this.processSelectedFiles(input, isFolder);
      },
      { once: true }
    );
    input.click();
  }

  private async processSelectedFiles(
    input: HTMLInputElement,
    isFolder: boolean
  ): Promise<void> {
    const fallbackFiles = input.files ? Array.from(input.files) : [];
    let files = fallbackFiles;
    let emptyDirs: string[] = [];
    if (isFolder) {
      const selected = await this.collectSelectedDirectoryEntries(input);
      if (selected.files.length > 0) {
        files = selected.files;
      }
      emptyDirs = selected.emptyDirs;
    }
    if (emptyDirs.length > 0) {
      this.events.emit({
        name: 'send_empty_dirs',
        dirs: JSON.stringify(emptyDirs)
      });
    }
    if (files.length === 0) {
      return;
    }
    const handleIndex = this.nextFileHandle++;
    this.fileHandles.set(handleIndex, files);
    this.emitSelectedFiles(handleIndex, files);
  }

  private emitSelectedFiles(handleIndex: number, files: File[]): void {
    for (const file of files) {
      const relative = (file as File & { webkitRelativePath?: string })
        .webkitRelativePath;
      const name = relative && relative.length > 0 ? relative : file.name;
      const entry = {
        entry_type: 4,
        name,
        size: file.size ?? 0,
        modified_time: Math.floor((file.lastModified || Date.now()) / 1000)
      };
      this.events.emit({
        name: 'selected_files',
        handleIndex: String(handleIndex),
        file: JSON.stringify(entry)
      });
    }
  }

  private async collectSelectedDirectoryEntries(
    input: HTMLInputElement
  ): Promise<{ files: File[]; emptyDirs: string[] }> {
    const rootEntries = input.webkitEntries ? Array.from(input.webkitEntries) : [];
    if (rootEntries.length === 0) {
      return { files: input.files ? Array.from(input.files) : [], emptyDirs: [] };
    }
    const files: File[] = [];
    const emptyDirs: string[] = [];
    for (const entry of rootEntries) {
      await this.walkFileSystemEntry(entry, '', files, emptyDirs);
    }
    return { files, emptyDirs };
  }

  private async walkFileSystemEntry(
    entry: FileSystemEntry,
    parentPath: string,
    files: File[],
    emptyDirs: string[]
  ): Promise<void> {
    const currentPath = parentPath ? `${parentPath}/${entry.name}` : entry.name;
    if (entry.isFile) {
      files.push(
        await this.readFileSystemEntry(entry as FileSystemFileEntry, currentPath)
      );
      return;
    }
    const children = await this.readAllDirectoryEntries(
      entry as FileSystemDirectoryEntry
    );
    if (children.length === 0) {
      emptyDirs.push(currentPath);
      return;
    }
    for (const child of children) {
      await this.walkFileSystemEntry(child, currentPath, files, emptyDirs);
    }
  }

  private readAllDirectoryEntries(
    entry: FileSystemDirectoryEntry
  ): Promise<FileSystemEntry[]> {
    const reader = entry.createReader();
    const collected: FileSystemEntry[] = [];
    const readBatch = (): Promise<FileSystemEntry[]> =>
      new Promise((resolve, reject) => {
        reader.readEntries(resolve, reject);
      });
    const loop = async (): Promise<FileSystemEntry[]> => {
      const batch = await readBatch();
      if (batch.length === 0) {
        return collected;
      }
      collected.push(...batch);
      return loop();
    };
    return loop();
  }

  private readFileSystemEntry(
    entry: FileSystemFileEntry,
    relativePath: string
  ): Promise<File> {
    return new Promise((resolve, reject) => {
      entry.file((file) => {
        this.attachRelativePath(file, relativePath);
        resolve(file);
      }, reject);
    });
  }

  private async rehydrateDroppedFile(
    file: DroppedFilePayload
  ): Promise<File | null> {
    const uri = String(file.uri ?? '').trim();
    const name = String(file.name ?? '').trim();
    if (!uri || !name) {
      return null;
    }
    try {
      const response = await fetch(uri);
      if (!response.ok) {
        throw new Error(`failed to fetch dropped file: ${response.status}`);
      }
      const blob = await response.blob();
      const next = new File([blob], name, {
        type: String(file.mime_type ?? ''),
        lastModified: Number(file.last_modified ?? Date.now())
      });
      const relativePath = String(file.relative_path ?? '').trim();
      if (relativePath) {
        this.attachRelativePath(next, relativePath);
      }
      return next;
    } catch (err) {
      this.logger.warn(`Failed to rehydrate dropped file '${name}'`, err);
      return null;
    }
  }

  private attachRelativePath(file: File, relativePath: string): void {
    if (!relativePath || relativePath === file.name) {
      return;
    }
    Object.defineProperty(file, 'webkitRelativePath', {
      value: relativePath,
      configurable: true
    });
  }

  private handleQueryOnlines(arg0?: unknown): void {
    const ids = this.normalizeIdList(this.parseIdList(arg0));
    if (ids.length === 0) {
      this.closeOnlineQueryTransport();
      this.emitQueryOnlines([], []);
      return;
    }
    this.pendingOnlineQueryIds = ids;
    if (this.queryOnlinesInFlight) {
      return;
    }
    void this.flushOnlineQueries();
  }

  private parseIdList(arg0?: unknown): string[] {
    if (typeof arg0 === 'string') {
      try {
        const parsed = JSON.parse(arg0) as unknown;
        if (Array.isArray(parsed)) {
          return parsed.map((id) => String(id));
        }
      } catch {
        return [];
      }
    }
    if (Array.isArray(arg0)) {
      return arg0.map((id) => String(id));
    }
    return [];
  }

  private normalizeIdList(ids: string[]): string[] {
    const unique: string[] = [];
    const seen = new Set<string>();
    for (const value of ids) {
      const id = String(value ?? '').trim();
      if (!id || seen.has(id)) {
        continue;
      }
      seen.add(id);
      unique.push(id);
    }
    return unique;
  }

  private async flushOnlineQueries(): Promise<void> {
    if (this.queryOnlinesInFlight) {
      return;
    }
    this.queryOnlinesInFlight = true;
    try {
      while (this.pendingOnlineQueryIds && this.pendingOnlineQueryIds.length > 0) {
        const ids = this.pendingOnlineQueryIds;
        this.pendingOnlineQueryIds = undefined;
        await this.queryOnlineStates(ids);
      }
    } finally {
      this.queryOnlinesInFlight = false;
    }
  }

  private emitQueryOnlines(onlines: string[], offlines: string[]): void {
    this.events.emit({
      name: 'callback_query_onlines',
      onlines: onlines.join(','),
      offlines: offlines.join(',')
    });
  }

  private async queryOnlineStates(ids: string[]): Promise<void> {
    const context = this.buildSessionContext();
    const rendezvousServer =
      this.resolveRendezvousServer() || context.rendezvousServer;
    if (!rendezvousServer) {
      this.emitQueryOnlines([], ids);
      return;
    }
    const onlineServer = this.deriveOnlineServer(rendezvousServer);
    const endpoint = checkWsEndpoint(
      onlineServer,
      context.relayServer,
      context.apiServer,
      'auto',
      rendezvousServer,
      context.defaultIdPort
    );
    if (!endpoint) {
      this.emitQueryOnlines([], ids);
      return;
    }
    const proto = await this.ensureProto();
    let transport: WebSocketTransport | undefined;
    let inbox: MessageInbox | undefined;
    try {
      transport = await this.ensureOnlineQueryTransport(endpoint);
      inbox = new MessageInbox(transport);
      const request = {
        onlineRequest: {
          id: context.myId,
          peers: ids
        }
      };
      transport.send(proto.rendezvousType.encode(request).finish());

      for (let attempt = 0; attempt < 2; attempt++) {
        let data: Uint8Array;
        try {
          data = await inbox.next(3000);
        } catch {
          continue;
        }
        const msg = decodeProtoObject<Record<string, unknown>>(
          proto.rendezvousType,
          data,
          {
            longs: String,
            bytes: Uint8Array,
            defaults: false
          }
        );
        if (msg.keyExchange) {
          continue;
        }
        const onlineResponse = msg.onlineResponse as
          | { states?: Uint8Array }
          | undefined;
        if (!onlineResponse) {
          continue;
        }
        const [onlines, offlines] = this.decodeOnlineStates(
          onlineResponse.states,
          ids
        );
        this.emitQueryOnlines(onlines, offlines);
        return;
      }
    } catch (err) {
      this.logger.warn('query_onlines failed', err);
      this.closeOnlineQueryTransport();
    } finally {
      inbox?.close();
      this.scheduleOnlineQueryTransportClose();
    }

    this.emitQueryOnlines([], ids);
  }

  private clearOnlineQueryCloseTimer(): void {
    if (this.onlineQueryCloseTimer !== undefined) {
      window.clearTimeout(this.onlineQueryCloseTimer);
      this.onlineQueryCloseTimer = undefined;
    }
  }

  private scheduleOnlineQueryTransportClose(delayMs = 30000): void {
    this.clearOnlineQueryCloseTimer();
    this.onlineQueryCloseTimer = window.setTimeout(() => {
      this.onlineQueryCloseTimer = undefined;
      this.closeOnlineQueryTransport();
    }, delayMs);
  }

  private closeOnlineQueryTransport(): void {
    this.clearOnlineQueryCloseTimer();
    if (this.onlineQueryTransport) {
      this.onlineQueryTransport.close();
      this.onlineQueryTransport = undefined;
    }
    this.onlineQueryEndpoint = '';
  }

  private async ensureOnlineQueryTransport(
    endpoint: string
  ): Promise<WebSocketTransport> {
    this.clearOnlineQueryCloseTimer();
    if (!this.onlineQueryTransport || this.onlineQueryEndpoint !== endpoint) {
      this.closeOnlineQueryTransport();
      this.onlineQueryTransport = new WebSocketTransport('online');
      this.onlineQueryEndpoint = endpoint;
    }
    if (this.onlineQueryTransport.getState() !== 'open') {
      await this.onlineQueryTransport.connect(endpoint, 5000);
    }
    return this.onlineQueryTransport;
  }

  private decodeOnlineStates(
    states: Uint8Array | undefined,
    ids: string[]
  ): [string[], string[]] {
    if (!states || states.length === 0) {
      return [[], ids.slice()];
    }
    const onlines: string[] = [];
    const offlines: string[] = [];
    for (let i = 0; i < ids.length; i++) {
      const byteIndex = Math.floor(i / 8);
      const bitValue = 0x01 << (7 - (i % 8));
      if ((states[byteIndex] & bitValue) === bitValue) {
        onlines.push(ids[i]);
      } else {
        offlines.push(ids[i]);
      }
    }
    return [onlines, offlines];
  }

  private deriveOnlineServer(endpoint: string): string {
    if (!endpoint || endpoint.startsWith('ws://') || endpoint.startsWith('wss://')) {
      return endpoint;
    }
    const fallbackOnlinePort = this.offsetPort(this.getDefaultIdPort(), -1);
    const normalized = endpoint.includes('://')
      ? this.stripSchemeAndPath(endpoint)
      : endpoint;
    const parsed = this.splitHostPort(normalized);
    if (!parsed) {
      if (!normalized) {
        return normalized;
      }
      if (normalized.startsWith('[') && normalized.endsWith(']')) {
        return `${normalized}:${fallbackOnlinePort}`;
      }
      if (normalized.includes(':')) {
        return `[${normalized}]:${fallbackOnlinePort}`;
      }
      return `${normalized}:${fallbackOnlinePort}`;
    }
    const port = parsed.port > 0 ? parsed.port - 1 : parsed.port;
    return parsed.isIpv6
      ? `[${parsed.host}]:${port}`
      : `${parsed.host}:${port}`;
  }

  private startAccountAuth(arg0?: unknown): void {
    const payload =
      typeof arg0 === 'string'
        ? (this.safeJson(arg0) as AccountAuthPayload)
        : (arg0 as AccountAuthPayload | undefined) ?? {};
    const op = String(payload.op ?? '').trim();
    const remember = Boolean(payload.remember);
    if (!op) {
      this.updateAccountAuthResult({
        state_msg: 'Requesting account auth',
        failed_msg: 'Invalid auth op',
        url: '',
        url_launched: false
      });
      return;
    }

    const apiServer = this.resolveApiServer();
    if (!apiServer) {
      this.updateAccountAuthResult({
        state_msg: 'Requesting account auth',
        failed_msg: 'API server not configured',
        url: '',
        url_launched: false
      });
      return;
    }

    this.cancelAccountAuth(false);
    this.accountAuthPopup = this.openAccountAuthPopup();
    const nonce = ++this.accountAuthNonce;
    const controller = new AbortController();
    this.accountAuthAbort = controller;

    this.updateAccountAuthResult({
      state_msg: 'Requesting account auth',
      failed_msg: '',
      url: '',
      url_launched: false
    });

    const id = this.store.get('my_id', this.config.profile.id ?? '');
    const uuid = this.store.ensure('uuid', generateUuid);
    const deviceInfo = this.buildDeviceInfo();

    void this.performAccountAuth({
      nonce,
      apiServer,
      op,
      remember,
      id,
      uuid,
      deviceInfo,
      signal: controller.signal
    });
  }

  private cancelAccountAuth(clearResult = true): void {
    this.accountAuthNonce++;
    if (this.accountAuthAbort) {
      this.accountAuthAbort.abort();
      this.accountAuthAbort = undefined;
    }
    this.closeAccountAuthPopup();
    if (clearResult) {
      this.store.set('account_auth_result', '');
    }
  }

  private openAccountAuthPopup(): Window | null {
    try {
      const popup = window.open('', '_blank');
      if (!popup) {
        return null;
      }
      try {
        popup.opener = null;
      } catch {}
      return popup;
    } catch {
      return null;
    }
  }

  private launchAccountAuthUrl(url: string): boolean {
    if (!url) {
      return false;
    }
    const popup = this.accountAuthPopup;
    if (popup && !popup.closed) {
      try {
        popup.location.replace(url);
        popup.focus();
        return true;
      } catch {}
    }
    return false;
  }

  private closeAccountAuthPopup(): void {
    const popup = this.accountAuthPopup;
    this.accountAuthPopup = null;
    if (!popup || popup.closed) {
      return;
    }
    try {
      popup.close();
    } catch {}
  }

  private async performAccountAuth(args: {
    nonce: number;
    apiServer: string;
    op: string;
    remember: boolean;
    id: string;
    uuid: string;
    deviceInfo: { os: string; type: string; name: string };
    signal: AbortSignal;
  }): Promise<void> {
    const { nonce, apiServer, op, remember, id, uuid, deviceInfo, signal } = args;
    let authUrl = '';
    let urlLaunched = false;
    try {
      const authResponse = (await this.fetchJson(
        `${apiServer}/api/oidc/auth`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            op,
            id,
            uuid,
            deviceInfo
          }),
          signal
        }
      )) as OidcAuthUrlResponse;

      if (!this.isAccountAuthActive(nonce)) {
        return;
      }
      if (authResponse.error) {
        this.closeAccountAuthPopup();
        this.updateAccountAuthResult({
          state_msg: 'Requesting account auth',
          failed_msg: authResponse.error,
          url: '',
          url_launched: false
        });
        return;
      }
      if (!authResponse.code || !authResponse.url) {
        this.closeAccountAuthPopup();
        this.updateAccountAuthResult({
          state_msg: 'Requesting account auth',
          failed_msg: 'Invalid auth response',
          url: '',
          url_launched: false
        });
        return;
      }

      authUrl = authResponse.url;
      urlLaunched = this.launchAccountAuthUrl(authUrl);
      this.updateAccountAuthResult({
        state_msg: 'Waiting account auth',
        failed_msg: '',
        url: authUrl,
        url_launched: urlLaunched
      });

      const queryUrl = new URL(`${apiServer}/api/oidc/auth-query`);
      queryUrl.searchParams.set('code', authResponse.code);
      queryUrl.searchParams.set('id', id);
      queryUrl.searchParams.set('uuid', uuid);

      const start = Date.now();
      const timeoutMs = 3 * 60 * 1000;
      while (this.isAccountAuthActive(nonce) && Date.now() - start < timeoutMs) {
        let queryResponse: OidcAuthQueryResponse | null = null;
        try {
          queryResponse = (await this.fetchJson(queryUrl.toString(), {
            method: 'GET',
            signal
          })) as OidcAuthQueryResponse;
        } catch (err) {
          if (signal.aborted || !this.isAccountAuthActive(nonce)) {
            return;
          }
          await this.sleep(1000);
          continue;
        }

        if (!this.isAccountAuthActive(nonce)) {
          return;
        }

        if (queryResponse?.error) {
          const errText = String(queryResponse.error);
          if (!errText.includes('No authed oidc is found')) {
            this.updateAccountAuthResult({
              state_msg: 'Waiting account auth',
              failed_msg: errText,
              url: authUrl,
              url_launched: urlLaunched
            });
            return;
          }
        } else if (queryResponse?.type) {
          if (remember && queryResponse.type === 'access_token') {
            this.storeAuthToken(queryResponse);
          }
          this.closeAccountAuthPopup();
          this.updateAccountAuthResult({
            state_msg: 'Login account auth',
            failed_msg: '',
            url: authUrl,
            url_launched: urlLaunched,
            auth_body: queryResponse
          });
          return;
        }

        await this.sleep(1000);
      }

      if (this.isAccountAuthActive(nonce)) {
        this.updateAccountAuthResult({
          state_msg: 'Waiting account auth',
          failed_msg: 'timeout',
          url: authUrl,
          url_launched: urlLaunched
        });
      }
    } catch (err) {
      if (!this.isAccountAuthActive(nonce)) {
        return;
      }
      if (!authUrl) {
        this.closeAccountAuthPopup();
      }
      const message =
        err instanceof Error ? err.message : 'Failed to request auth';
      this.updateAccountAuthResult({
        state_msg: 'Requesting account auth',
        failed_msg: message,
        url: authUrl,
        url_launched: urlLaunched
      });
    }
  }

  private updateAccountAuthResult(result: AccountAuthResult): void {
    this.store.set('account_auth_result', JSON.stringify(result));
  }

  private isAccountAuthActive(nonce: number): boolean {
    return nonce === this.accountAuthNonce;
  }

  private storeAuthToken(auth: OidcAuthQueryResponse): void {
    if (!auth.access_token) {
      return;
    }
    const token = String(auth.access_token);
    this.store.set('option:local:access_token', token);
    this.store.set('option:access_token', token);
    if (auth.user) {
      this.store.set('option:local:user_info', JSON.stringify(auth.user));
    }
  }

  private applyBootstrapConfig(arg0?: unknown): void {
    let payload: BootstrapConfigPayload | null = null;
    if (typeof arg0 === 'string') {
      payload = this.safeJson(arg0) as BootstrapConfigPayload;
    } else if (arg0 && typeof arg0 === 'object') {
      payload = arg0 as BootstrapConfigPayload;
    }
    if (!payload) {
      return;
    }
    if (typeof payload.appName === 'string' && payload.appName.trim()) {
      this.config.appName = payload.appName.trim();
    }
    if (typeof payload.version === 'string' && payload.version.trim()) {
      this.config.version = payload.version.trim();
    }
    if (typeof payload.buildDate === 'string' && payload.buildDate.trim()) {
      this.config.buildDate = payload.buildDate.trim();
    }
    if (typeof payload.apiServer === 'string' && payload.apiServer.trim()) {
      this.config.apiServer = this.normalizeApiServer(payload.apiServer.trim());
    }
    const rendezvousServers = this.parseServerList(payload.rendezvousServers);
    if (rendezvousServers.length > 0) {
      this.config.rendezvousServers = rendezvousServers;
    }
    const relayServers = this.parseServerList(payload.relayServers);
    if (relayServers.length > 0) {
      this.config.relayServers = relayServers;
    }
    if (typeof payload.rsPubKey === 'string') {
      this.setEnvValue('RS_PUB_KEY', payload.rsPubKey);
    }
    if (payload.env && typeof payload.env === 'object') {
      for (const [key, value] of Object.entries(payload.env)) {
        this.setEnvValue(key, value ?? '');
      }
    }
    if (typeof payload.isPublicServer === 'boolean') {
      this.config.isPublicServer = payload.isPublicServer;
    }
    this.refreshDefaultOptions();
    this.startConnectStatusProbe();
  }

  private refreshDefaultOptions(): void {
    const rendezvousServers = this.getConfiguredRendezvousServers();
    const primaryRendezvous = rendezvousServers[0] ?? '';
    const rendezvousCsv = rendezvousServers.join(',');
    const apiServer = this.resolveApiServerFromConfig(primaryRendezvous);
    const relayServers = this.getConfiguredRelayServers(rendezvousServers, apiServer);
    const relayCsv = relayServers.join(',');
    const primaryRelay =
      relayServers[0] ?? this.deriveRelayServer(primaryRendezvous, apiServer);
    const key = this.getEnv('RS_PUB_KEY', 'rs_pub_key');
    const defaultIdPort = this.getDefaultIdPort();

    this.config.rendezvousServers = rendezvousServers;
    this.config.relayServers = relayServers;
    this.config.apiServer = apiServer;

    this.optionDefaults.clear();
    this.optionDefaults.set('custom-rendezvous-server', rendezvousCsv || primaryRendezvous);
    this.optionDefaults.set('relay-server', relayCsv || primaryRelay);
    this.optionDefaults.set('api-server', apiServer);
    this.optionDefaults.set('key', key);
    this.optionDefaults.set('default-id-port', String(defaultIdPort));
    this.optionDefaults.set('verification-method', 'use-both-passwords');
    this.optionDefaults.set('approve-mode', 'password');
    this.optionDefaults.set('temporary-password-length', '6');
    this.optionDefaults.set('allow-numeric-one-time-password', 'N');
    this.optionDefaults.set('enable-direct-server', 'N');
    this.optionDefaults.set('direct-access-port', String(this.defaultWsIdPort()));
    this.optionDefaults.set('allow-websocket', 'Y');
    this.optionDefaults.set('enable-trusted-devices', 'Y');
    this.optionDefaults.set('disable-udp', 'Y');

    this.localOptionDefaults.clear();
    this.localOptionDefaults.set('lang', 'default');
    this.localOptionDefaults.set('disable-discovery-panel', 'Y');
    this.localOptionDefaults.set('input-source', 'Input source 1');

    this.flutterLocalOptionDefaults.clear();
    this.flutterLocalOptionDefaults.set('peer-tab-index', '0');
    this.flutterLocalOptionDefaults.set('peer-tab-order', '[0,1,2,3,4]');
    this.flutterLocalOptionDefaults.set(
      'peer-tab-visible',
      '[true,true,false,true,true]'
    );

    this.userDefaultOptionDefaults.clear();
    this.userDefaultOptionDefaults.set('view_style', 'original');
    this.userDefaultOptionDefaults.set('scroll_style', 'scrollauto');
    this.userDefaultOptionDefaults.set('image_quality', 'balanced');
    this.userDefaultOptionDefaults.set('codec-preference', 'auto');
    this.userDefaultOptionDefaults.set('custom_image_quality', '100');
    this.userDefaultOptionDefaults.set('custom-fps', '60');
    this.userDefaultOptionDefaults.set('show_remote_cursor', 'Y');
    this.userDefaultOptionDefaults.set('view_only', 'N');
    this.userDefaultOptionDefaults.set('show_monitors_toolbar', 'N');
    this.userDefaultOptionDefaults.set('collapse_toolbar', 'N');
    this.userDefaultOptionDefaults.set('follow_remote_cursor', 'N');
    this.userDefaultOptionDefaults.set('follow_remote_window', 'N');
    this.userDefaultOptionDefaults.set('zoom-cursor', 'N');
    this.userDefaultOptionDefaults.set('show_quality_monitor', 'N');
    this.userDefaultOptionDefaults.set('disable_audio', 'N');
    this.userDefaultOptionDefaults.set('enable-file-copy-paste', 'Y');
    this.userDefaultOptionDefaults.set('disable_clipboard', 'N');
    this.userDefaultOptionDefaults.set('lock_after_session_end', 'N');
    this.userDefaultOptionDefaults.set('privacy_mode', 'N');
    this.userDefaultOptionDefaults.set('i444', 'N');
    this.userDefaultOptionDefaults.set('reverse_mouse_wheel', 'N');
    this.userDefaultOptionDefaults.set('swap-left-right-mouse', 'N');
    this.userDefaultOptionDefaults.set('displays_as_individual_windows', 'N');
    this.userDefaultOptionDefaults.set(
      'use_all_my_displays_for_the_remote_session',
      'N'
    );
    this.userDefaultOptionDefaults.set('terminal-persistent', 'N');
    this.userDefaultOptionDefaults.set('edge-scroll-edge-thickness', '100');
    this.userDefaultOptionDefaults.set('trackpad-speed', '100');

  }

  private getConfiguredRendezvousServers(): string[] {
    const fromConfig = this.normalizeServerList(this.config.rendezvousServers);
    if (fromConfig.length > 0) {
      return fromConfig;
    }
    return this.parseServerList(this.getEnv('RENDEZVOUS_SERVERS', 'rendezvous_servers'));
  }

  private getConfiguredRelayServers(
    rendezvousServers: string[],
    apiServer: string
  ): string[] {
    const fromConfig = this.normalizeServerList(this.config.relayServers);
    if (fromConfig.length > 0) {
      return fromConfig;
    }
    const fromEnv = this.parseServerList(this.getEnv('RELAY_SERVER', 'relay_server'));
    if (fromEnv.length > 0) {
      return fromEnv;
    }
    const derived = rendezvousServers
      .map((server) => this.deriveRelayServer(server, apiServer))
      .filter((server) => server.length > 0);
    if (derived.length > 0) {
      return derived;
    }
    const single = this.deriveRelayServer(rendezvousServers[0] ?? '', apiServer);
    return single ? [single] : [];
  }

  private parseServerList(input?: string[] | string): string[] {
    if (Array.isArray(input)) {
      return this.normalizeServerList(
        input.flatMap((item) => String(item ?? '').split(/[,\s;]+/))
      );
    }
    if (typeof input !== 'string') {
      return [];
    }
    return this.normalizeServerList(input.split(/[,\s;]+/));
  }

  private normalizeServerList(list: string[]): string[] {
    const out: string[] = [];
    for (const item of list) {
      const normalized = String(item ?? '').trim();
      if (normalized && !out.includes(normalized)) {
        out.push(normalized);
      }
    }
    return out;
  }

  private getEnv(...keys: string[]): string {
    for (const key of keys) {
      const values = [
        this.config.env[key],
        this.config.env[key.toUpperCase()],
        this.config.env[key.toLowerCase()]
      ];
      for (const value of values) {
        if (typeof value === 'string' && value.trim()) {
          return value.trim();
        }
      }
    }
    return '';
  }

  private setEnvValue(key: string, value: unknown): void {
    const normalized = String(value ?? '').trim();
    this.config.env[key] = normalized;
    this.store.set(`envvar:${key}`, normalized);
    const lower = key.toLowerCase();
    if (
      lower === 'rs_pub_key' ||
      lower === 'rendezvous_servers' ||
      lower === 'api_server' ||
      lower === 'relay_server' ||
      lower === 'default_id_port'
    ) {
      this.refreshDefaultOptions();
      this.startConnectStatusProbe();
    }
  }

  private resolveApiServerFromConfig(rendezvousServer = ''): string {
    const direct = this.normalizeApiServer(
      this.config.apiServer || this.getEnv('API_SERVER', 'api_server')
    );
    if (direct) {
      return direct;
    }
    const source = rendezvousServer || this.config.rendezvousServers[0] || '';
    if (!source) {
      return '';
    }
    const stripped = this.stripSchemeAndPath(source);
    const adjusted = this.increasePort(stripped, -2);
    if (adjusted === stripped) {
      return this.normalizeApiServer(this.appendPort(stripped, 21114));
    }
    return this.normalizeApiServer(adjusted);
  }

  private resolveApiServer(): string {
    const direct = this.getOption('api-server');
    if (direct) {
      return this.normalizeApiServer(direct);
    }
    const custom = this.getOption('custom-rendezvous-server');
    if (custom) {
      const primaryCustom = this.parseServerList(custom)[0] ?? custom;
      const stripped = this.stripSchemeAndPath(primaryCustom);
      const adjusted = this.increasePort(stripped, -2);
      if (adjusted === stripped) {
        return this.normalizeApiServer(this.appendPort(stripped, 21114));
      }
      return this.normalizeApiServer(adjusted);
    }
    return this.resolveApiServerFromConfig();
  }

  private resolveRendezvousServer(): string {
    const custom = this.getOption('custom-rendezvous-server');
    const apiServer = this.resolveApiServer();
    const customList = this.parseServerList(custom);
    for (const candidate of customList) {
      const normalized = this.normalizeRendezvousServer(candidate, apiServer);
      if (normalized) {
        return normalized;
      }
    }
    for (const candidate of this.getConfiguredRendezvousServers()) {
      const normalized = this.normalizeRendezvousServer(candidate, apiServer);
      if (normalized) {
        return normalized;
      }
    }
    return '';
  }

  private resolveRelayServer(rendezvousServer: string): string {
    const relay = this.getOption('relay-server');
    const apiServer = this.resolveApiServer();
    if (relay) {
      const relayList = this.parseServerList(relay);
      for (const candidate of relayList) {
        const normalized = this.normalizeRelayServer(
          candidate,
          apiServer,
          rendezvousServer
        );
        if (normalized) {
          return normalized;
        }
      }
    }
    return this.deriveRelayServer(rendezvousServer, apiServer);
  }

  private deriveRelayServer(rendezvousServer: string, apiServer = ''): string {
    const rendezvous = this.normalizeRendezvousServer(rendezvousServer, apiServer);
    const parsed = this.parseServerInput(rendezvous);
    if (!parsed) {
      return '';
    }
    if (!parsed.scheme) {
      const basePort = parsed.port ?? this.getDefaultIdPort();
      return this.formatHostPort(
        parsed.host,
        this.offsetPort(basePort, 1),
        parsed.isIpv6
      );
    }
    const basePort = parsed.port ?? this.defaultWsIdPort();
    const relayPort = this.offsetPort(basePort, 1);
    const scheme = parsed.scheme === 'wss' ? 'wss' : 'ws';
    return this.formatWebSocketServer(scheme, parsed.host, relayPort, parsed.isIpv6);
  }

  private normalizeRendezvousServer(server: string, apiServer: string): string {
    const parsed = this.parseServerInput(server);
    if (!parsed) {
      return '';
    }
    const defaultIdPort = this.getDefaultIdPort();
    if (parsed.scheme && parsed.scheme !== 'ws' && parsed.scheme !== 'wss') {
      return '';
    }
    if (parsed.scheme === 'ws') {
      const port = parsed.port ?? this.offsetPort(defaultIdPort, 2);
      return this.formatWebSocketServer('ws', parsed.host, port, parsed.isIpv6);
    }
    if (parsed.scheme === 'wss') {
      const port = parsed.port ?? this.offsetPort(defaultIdPort, 2);
      return this.formatWebSocketServer('wss', parsed.host, port, parsed.isIpv6);
    }
    const port = parsed.port ?? defaultIdPort;
    return this.formatHostPort(parsed.host, port, parsed.isIpv6);
  }

  private normalizeRelayServer(
    server: string,
    apiServer: string,
    rendezvousServer: string
  ): string {
    const parsed = this.parseServerInput(server);
    if (!parsed) {
      return '';
    }
    if (parsed.scheme && parsed.scheme !== 'ws' && parsed.scheme !== 'wss') {
      return '';
    }
    const defaultIdPort = this.getDefaultIdPort();
    const fallback = this.parseServerInput(
      this.normalizeRendezvousServer(rendezvousServer, apiServer)
    );
    const fallbackNativeIdPort = fallback
      ? fallback.scheme
        ? this.offsetPort(fallback.port ?? this.defaultWsIdPort(), -2)
        : (fallback.port ?? defaultIdPort)
      : defaultIdPort;
    if (parsed.scheme === 'ws' || parsed.scheme === 'wss') {
      const webRelayPort = parsed.port ?? this.offsetPort(fallbackNativeIdPort, 3);
      return this.formatWebSocketServer(
        parsed.scheme,
        parsed.host,
        webRelayPort,
        parsed.isIpv6
      );
    }
    const port = parsed.port ?? this.offsetPort(fallbackNativeIdPort, 1);
    return this.formatHostPort(parsed.host, port, parsed.isIpv6);
  }

  private formatWebSocketServer(
    scheme: 'ws' | 'wss',
    host: string,
    port: number,
    isIpv6: boolean
  ): string {
    const finalHost = isIpv6 ? `[${host}]` : host;
    return `${scheme}://${finalHost}:${port}`;
  }

  private formatHostPort(host: string, port: number, isIpv6: boolean): string {
    const finalHost = isIpv6 ? `[${host}]` : host;
    return `${finalHost}:${port}`;
  }

  private parseServerInput(
    input: string
  ): { scheme: 'ws' | 'wss' | null; host: string; port: number | null; isIpv6: boolean; isIp: boolean } | null {
    const raw = input.trim();
    if (!raw) {
      return null;
    }
    if (raw.includes('://')) {
      try {
        const url = new URL(raw);
        const protocol = url.protocol.replace(':', '').toLowerCase();
        if (protocol !== 'ws' && protocol !== 'wss') {
          return null;
        }
        const host = url.hostname;
        if (!host) {
          return null;
        }
        const explicitPortFromRaw = this.parseExplicitPortFromUrlInput(raw);
        const portText = url.port;
        let port: number | null = null;
        if (portText) {
          const numeric = Number.parseInt(portText, 10);
          if (!Number.isInteger(numeric) || numeric <= 0 || numeric > 65535) {
            return null;
          }
          port = numeric;
        } else if (explicitPortFromRaw !== null) {
          port = explicitPortFromRaw;
        }
        const normalizedHost = this.stripIpv6Brackets(host);
        const isIpv6 = normalizedHost.includes(':');
        return {
          scheme: protocol,
          host: normalizedHost,
          port,
          isIpv6,
          isIp: this.isIpAddress(normalizedHost)
        };
      } catch {
        return null;
      }
    }
    const stripped = this.stripSchemeAndPath(raw);
    const split = this.splitHostPort(stripped);
    if (split) {
      const normalizedHost = this.stripIpv6Brackets(split.host);
      return {
        scheme: null,
        host: normalizedHost,
        port: split.port,
        isIpv6: split.isIpv6 || normalizedHost.includes(':'),
        isIp: this.isIpAddress(normalizedHost)
      };
    }
    const normalizedHost = this.stripIpv6Brackets(stripped);
    if (!normalizedHost) {
      return null;
    }
    return {
      scheme: null,
      host: normalizedHost,
      port: null,
      isIpv6: normalizedHost.includes(':'),
      isIp: this.isIpAddress(normalizedHost)
    };
  }

  private parseExplicitPortFromUrlInput(raw: string): number | null {
    const schemeIdx = raw.indexOf('://');
    if (schemeIdx < 0) {
      return null;
    }
    const afterScheme = raw.slice(schemeIdx + 3);
    const authEnd = afterScheme.search(/[/?#]/);
    const authority = (authEnd >= 0 ? afterScheme.slice(0, authEnd) : afterScheme).trim();
    if (!authority) {
      return null;
    }
    if (authority.startsWith('[')) {
      const end = authority.indexOf(']');
      if (end <= 0) {
        return null;
      }
      const rest = authority.slice(end + 1);
      if (!rest.startsWith(':')) {
        return null;
      }
      const value = Number.parseInt(rest.slice(1), 10);
      if (!Number.isInteger(value) || value <= 0 || value > 65535) {
        return null;
      }
      return value;
    }
    const firstColon = authority.indexOf(':');
    const lastColon = authority.lastIndexOf(':');
    if (firstColon < 0 || firstColon !== lastColon) {
      return null;
    }
    const value = Number.parseInt(authority.slice(lastColon + 1), 10);
    if (!Number.isInteger(value) || value <= 0 || value > 65535) {
      return null;
    }
    return value;
  }

  private stripIpv6Brackets(host: string): string {
    if (host.startsWith('[') && host.endsWith(']')) {
      return host.slice(1, -1);
    }
    return host;
  }

  private isIpAddress(host: string): boolean {
    const normalized = this.stripIpv6Brackets(host.trim());
    return this.isIpv4Address(normalized) || normalized.includes(':');
  }

  private isIpv4Address(host: string): boolean {
    const parts = host.split('.');
    if (parts.length !== 4) {
      return false;
    }
    return parts.every((part) => {
      if (!/^\d+$/.test(part)) {
        return false;
      }
      const value = Number.parseInt(part, 10);
      return Number.isInteger(value) && value >= 0 && value <= 255;
    });
  }

  private isUsingPublicServer(): boolean {
    const apiServer = this.resolveApiServer();
    if (!apiServer) {
      return this.config.isPublicServer;
    }
    try {
      const host = new URL(this.normalizeApiServer(apiServer)).hostname.toLowerCase();
      return host === 'camellia.aimmv.com' || host.endsWith('.camellia.aimmv.com');
    } catch {
      const value = apiServer.toLowerCase();
      return value.includes('camellia.aimmv.com');
    }
  }

  private normalizeApiServer(endpoint: string): string {
    let value = endpoint.trim();
    value = value.replace(/\/+$/, '');
    if (!value) {
      return '';
    }
    if (value.includes('://')) {
      return value;
    }
    const protocol = window.location.protocol === 'https:' ? 'https://' : 'http://';
    return `${protocol}${value}`;
  }

  private stripSchemeAndPath(endpoint: string): string {
    const value = endpoint.trim();
    if (!value) {
      return '';
    }
    if (value.includes('://')) {
      try {
        const url = new URL(value);
        return url.host;
      } catch {
        // fall through
      }
    }
    return value.split('/')[0];
  }

  private increasePort(endpoint: string, offset: number): string {
    const parsed = this.splitHostPort(endpoint);
    if (!parsed) {
      return endpoint;
    }
    const next = parsed.port + offset;
    if (!Number.isFinite(next) || next <= 0) {
      return endpoint;
    }
    return parsed.isIpv6 ? `[${parsed.host}]:${next}` : `${parsed.host}:${next}`;
  }

  private appendPort(host: string, port: number): string {
    if (!host) {
      return '';
    }
    if (host.startsWith('[')) {
      return `${host}:${port}`;
    }
    if (host.includes(':')) {
      return `[${host}]:${port}`;
    }
    return `${host}:${port}`;
  }

  private splitHostPort(
    endpoint: string
  ): { host: string; port: number; isIpv6: boolean } | null {
    if (!endpoint) {
      return null;
    }
    if (endpoint.startsWith('[')) {
      const end = endpoint.indexOf(']');
      if (end === -1) {
        return null;
      }
      const host = endpoint.slice(1, end);
      const rest = endpoint.slice(end + 1);
      if (!rest.startsWith(':')) {
        return null;
      }
      const port = Number(rest.slice(1));
      if (!Number.isFinite(port)) {
        return null;
      }
      return { host, port, isIpv6: true };
    }
    const lastColon = endpoint.lastIndexOf(':');
    if (lastColon === -1) {
      return null;
    }
    const colonCount = (endpoint.match(/:/g) ?? []).length;
    if (colonCount > 1) {
      return null;
    }
    const host = endpoint.slice(0, lastColon);
    const port = Number(endpoint.slice(lastColon + 1));
    if (!Number.isFinite(port)) {
      return null;
    }
    return { host, port, isIpv6: false };
  }

  private buildDeviceInfo(): { os: string; type: string; name: string } {
    const os = detectOs() || 'Web';
    const name = navigator.userAgent || navigator.platform || 'Web';
    return {
      os,
      type: 'browser',
      name
    };
  }

  private async fetchJson(
    url: string,
    init: RequestInit
  ): Promise<Record<string, unknown>> {
    const response = await fetch(url, init);
    const text = await response.text();
    if (!text) {
      if (!response.ok) {
        return { error: `HTTP ${response.status}` };
      }
      return {};
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(text) as Record<string, unknown>;
    } catch {
      if (!response.ok) {
        return { error: `HTTP ${response.status}` };
      }
      throw new Error('Invalid JSON response');
    }
    if (!response.ok && !('error' in parsed)) {
      parsed.error = `HTTP ${response.status}`;
    }
    return parsed;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      window.setTimeout(resolve, ms);
    });
  }

  private async ensureProto(): Promise<ProtoRoots> {
    if (!this.protoPromise) {
      this.protoPromise = loadProtos();
    }
    return this.protoPromise;
  }

  private emitJobError(id: number | undefined, err: string): void {
    this.events.emit({
      name: 'job_error',
      id: String(id ?? 0),
      err
    });
  }

  private computeAlternativeCodecs(): string {
    const peer = this.currentSession?.getPeerEncoding() ?? {};
    const decoding = this.currentSession?.getDecoding();
    const result = {
      vp8: Boolean(peer.vp8 && decoding?.vp8),
      av1: Boolean(peer.av1 && decoding?.av1),
      h264: Boolean(peer.h264 && decoding?.h264),
      h265: Boolean(peer.h265 && decoding?.h265)
    };
    return JSON.stringify(result);
  }

  private getVersionNumber(v: string): number {
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

  private handleTranslate(arg0?: unknown): string {
    if (typeof arg0 !== 'string') {
      return '';
    }
    try {
      const parsed = JSON.parse(arg0) as { text?: string };
      const text = (parsed.text ?? '').trim();
      if (!text) {
        return '';
      }
      const fallback: Record<string, string> = {
        empty_recent_tip: 'No recent sessions yet.',
        empty_favorite_tip: 'No favorite devices yet.',
        empty_lan_tip: 'No LAN devices discovered yet.',
        empty_address_book_tip: 'Address book is empty.',
        input_source_1_tip: 'Input source 1',
        input_source_2_tip: 'Input source 2',
        verify_rustdesk_password_tip: 'Verify Camellia password',
        privacy_mode_impl_mag_tip: 'Mode 1',
        privacy_mode_impl_virtual_display_tip: 'Mode 2',
        privacy_mode_impl_mag: 'Mode 1',
        privacy_mode_impl_exclude_from_capture: 'Mode 1',
        privacy_mode_impl_virtual_display: 'Mode 2',
        remember_account_tip: 'Remember this account',
        'Password Required': 'Password required',
        'Logging in...': 'Logging in...',
        'Enter privacy mode': 'Enter privacy mode',
        'Exit privacy mode': 'Exit privacy mode',
        'Failed to turn off': 'Failed to turn off',
        whitelist_sep: 'Separated by comma, semicolon, spaces or new line',
        share_warning_tip: 'The fields above are shared and visible to others.',
        ab_web_console_tip: 'More on web console'
      };
      return fallback[text] ?? text;
    } catch {
      return '';
    }
  }

  private parseJsonArray(input: unknown): unknown[] {
    if (Array.isArray(input)) {
      return input;
    }
    if (typeof input !== 'string') {
      return [];
    }
    try {
      const parsed = JSON.parse(input) as unknown;
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  private normalizePeerRecord(input: unknown): Record<string, unknown> | null {
    if (!input || typeof input !== 'object') {
      return null;
    }
    const peer = input as Record<string, unknown>;
    const id = String(peer.id ?? '').trim();
    if (!id) {
      return null;
    }
    const record: Record<string, unknown> = {
      id,
      hash: String(peer.hash ?? ''),
      username: String(peer.username ?? ''),
      hostname: String(peer.hostname ?? ''),
      platform: String(peer.platform ?? ''),
      alias: String(peer.alias ?? ''),
      tags: Array.isArray(peer.tags) ? peer.tags : [],
      forceAlwaysRelay: String(peer.forceAlwaysRelay ?? 'false'),
      rdpPort: String(peer.rdpPort ?? ''),
      rdpUsername: String(peer.rdpUsername ?? ''),
      loginName: String(peer.loginName ?? peer.login_name ?? ''),
      device_group_name: String(peer.device_group_name ?? ''),
      note: String(peer.note ?? ''),
      same_server: peer.same_server
    };
    const options = this.getPeerOptions(id);
    if (options.alias) {
      record.alias = options.alias;
    }
    if (options.rdp_port) {
      record.rdpPort = options.rdp_port;
    }
    if (options.rdp_username) {
      record.rdpUsername = options.rdp_username;
    }
    if (options.note) {
      record.note = options.note;
    }
    if (options['force-always-relay']) {
      record.forceAlwaysRelay = options['force-always-relay'] === 'Y' ? 'true' : 'false';
    }
    return record;
  }

  private peerSkeleton(id: string): Record<string, unknown> {
    return this.normalizePeerRecord({ id }) as Record<string, unknown>;
  }

  private parsePeersFromRecentStore(): Record<string, unknown>[] {
    const peers = this.parseJsonArray(this.store.get('recent_peers', '[]'));
    return peers
      .map((peer) => this.normalizePeerRecord(peer))
      .filter((peer): peer is Record<string, unknown> => peer !== null);
  }

  private syncRecentPeersStoreFormat(): void {
    this.store.set('recent_peers', JSON.stringify(this.parsePeersFromRecentStore()));
  }

  private parsePeersFromAddressBookStore(): Record<string, unknown>[] {
    const raw = this.store.get('address_book', '');
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      if (Array.isArray(parsed)) {
        return parsed
          .map((peer) => this.normalizePeerRecord(peer))
          .filter((peer): peer is Record<string, unknown> => peer !== null);
      }
      const entries = Array.isArray(parsed.ab_entries) ? parsed.ab_entries : [];
      const result: Record<string, unknown>[] = [];
      for (const entry of entries) {
        if (!entry || typeof entry !== 'object') {
          continue;
        }
        const peers = Array.isArray((entry as Record<string, unknown>).peers)
          ? ((entry as Record<string, unknown>).peers as unknown[])
          : [];
        for (const peer of peers) {
          const normalized = this.normalizePeerRecord(peer);
          if (normalized) {
            result.push(normalized);
          }
        }
      }
      return result;
    } catch {
      return [];
    }
  }

  private parsePeersFromGroupStore(): Record<string, unknown>[] {
    const raw = this.store.get('groups', '');
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const peers = Array.isArray(parsed.peers) ? parsed.peers : [];
      return peers
        .map((peer) => this.normalizePeerRecord(peer))
        .filter((peer): peer is Record<string, unknown> => peer !== null);
    } catch {
      return [];
    }
  }

  private parsePeersFromLanStore(): Record<string, unknown>[] {
    const peers = this.parseJsonArray(this.store.get('lan_peers', '[]'));
    return peers
      .map((peer) => this.normalizePeerRecord(peer))
      .filter((peer): peer is Record<string, unknown> => peer !== null);
  }

  private getRecentPeers(): Record<string, unknown>[] {
    return this.parsePeersFromRecentStore();
  }

  private getLanPeers(): Record<string, unknown>[] {
    return this.parsePeersFromLanStore();
  }

  private getAllKnownPeers(): Record<string, unknown>[] {
    const merged = new Map<string, Record<string, unknown>>();
    for (const source of [
      this.parsePeersFromRecentStore(),
      this.parsePeersFromAddressBookStore(),
      this.parsePeersFromGroupStore(),
      this.parsePeersFromLanStore()
    ]) {
      for (const peer of source) {
        const id = String(peer.id ?? '').trim();
        if (!id) {
          continue;
        }
        if (!merged.has(id)) {
          merged.set(id, peer);
        } else {
          merged.set(id, { ...merged.get(id), ...peer });
        }
      }
    }
    return Array.from(merged.values());
  }

  private findPeerById(id: string): Record<string, unknown> | null {
    const target = id.trim();
    if (!target) {
      return null;
    }
    return this.getAllKnownPeers().find((peer) => String(peer.id ?? '') === target) ?? null;
  }

  private getFavoritePeers(): Record<string, unknown>[] {
    const favIds = this.parseJsonArray(this.store.get('fav', '[]'))
      .map((id) => String(id).trim())
      .filter((id) => id.length > 0);
    if (favIds.length === 0) {
      return [];
    }
    const known = new Map<string, Record<string, unknown>>();
    for (const peer of this.getAllKnownPeers()) {
      known.set(String(peer.id ?? ''), peer);
    }
    const peers: Record<string, unknown>[] = [];
    for (const id of favIds) {
      peers.push(known.get(id) ?? this.peerSkeleton(id));
    }
    return peers;
  }

  private emitPeerLoadEvent(name: string, peers: Record<string, unknown>[]): void {
    this.events.emit({
      name,
      peers: JSON.stringify(peers),
      ids: ''
    });
  }

  private updateCurrentPeerMetadataFromPeerInfo(event: Record<string, unknown>): void {
    const session = this.currentSession;
    if (!session) {
      return;
    }
    const peerId = session.getPeerId().trim();
    if (!peerId) {
      return;
    }
    const peers = this.parsePeersFromRecentStore();
    const index = peers.findIndex((peer) => String(peer.id ?? '') === peerId);
    const base =
      index >= 0 ? peers[index] : this.findPeerById(peerId) ?? this.peerSkeleton(peerId);
    const next: Record<string, unknown> = { ...base };
    let changed = false;
    for (const field of ['username', 'hostname', 'platform'] as const) {
      if (event[field] === undefined || event[field] === null) {
        continue;
      }
      const value = String(event[field] ?? '').trim();
      if (String(next[field] ?? '') === value) {
        continue;
      }
      next[field] = value;
      changed = true;
    }
    if (!changed) {
      return;
    }
    const normalized = this.normalizePeerRecord(next);
    if (!normalized) {
      return;
    }
    if (index >= 0) {
      peers[index] = normalized;
    } else {
      peers.unshift(normalized);
      if (peers.length > 200) {
        peers.length = 200;
      }
    }
    this.store.set('recent_peers', JSON.stringify(peers));
    this.emitPeerLoadEvent('load_recent_peers', peers);
    this.emitPeerLoadEvent('load_fav_peers', this.getFavoritePeers());
  }

  private recordRecentPeer(id: string): void {
    const peerId = id.trim();
    if (!peerId) {
      return;
    }
    const peers = this.parsePeersFromRecentStore();
    const index = peers.findIndex((peer) => String(peer.id ?? '') === peerId);
    const base = this.findPeerById(peerId) ?? this.peerSkeleton(peerId);
    if (index >= 0) {
      peers.splice(index, 1);
    }
    peers.unshift(base);
    if (peers.length > 200) {
      peers.length = 200;
    }
    this.store.set('recent_peers', JSON.stringify(peers));

    const newStored = this.parseJsonArray(this.store.get('new_stored_peers', '[]'))
      .map((entry) => String(entry))
      .filter((entry) => entry.length > 0);
    if (!newStored.includes(peerId)) {
      newStored.push(peerId);
      this.store.set('new_stored_peers', JSON.stringify(newStored));
    }

    this.emitPeerLoadEvent('load_recent_peers', peers);
    this.emitPeerLoadEvent('load_fav_peers', this.getFavoritePeers());
  }

  private removePeerById(id: string): void {
    const peerId = id.trim();
    if (!peerId) {
      return;
    }
    const peers = this.parsePeersFromRecentStore().filter(
      (peer) => String(peer.id ?? '') !== peerId
    );
    this.store.set('recent_peers', JSON.stringify(peers));
    const lanPeers = this.parsePeersFromLanStore().filter(
      (peer) => String(peer.id ?? '') !== peerId
    );
    this.store.set('lan_peers', JSON.stringify(lanPeers));
    const fav = this.parseJsonArray(this.store.get('fav', '[]'))
      .map((entry) => String(entry))
      .filter((entry) => entry.length > 0 && entry !== peerId);
    this.store.set('fav', JSON.stringify(fav));
    const newStored = this.parseJsonArray(this.store.get('new_stored_peers', '[]'))
      .map((entry) => String(entry))
      .filter((entry) => entry.length > 0 && entry !== peerId);
    this.store.set('new_stored_peers', JSON.stringify(newStored));
    this.emitPeerLoadEvent('load_recent_peers', peers);
    this.emitPeerLoadEvent('load_fav_peers', this.getFavoritePeers());
    this.emitPeerLoadEvent('load_lan_peers', lanPeers);
  }

  private getRecentPeersForAb(arg0?: unknown): string {
    const peers = this.getRecentPeers();
    let filters: string[] = [];
    if (typeof arg0 === 'string' && arg0.trim()) {
      filters = this.parseJsonArray(arg0)
        .map((id) => String(id).trim())
        .filter((id) => id.length > 0);
    }
    if (filters.length === 0) {
      return JSON.stringify(peers);
    }
    const filterSet = new Set(filters);
    return JSON.stringify(
      peers.filter((peer) => filterSet.has(String(peer.id ?? '').trim()))
    );
  }

  private getPeerSync(id: string): string {
    const peer = this.findPeerById(id);
    if (!peer) {
      return '{}';
    }
    const info = {
      hostname: String(peer.hostname ?? ''),
      username: String(peer.username ?? ''),
      platform: String(peer.platform ?? '')
    };
    return JSON.stringify({
      ...peer,
      info
    });
  }

  private testIfValidServer(server: string): string {
    const entries = this.parseServerList(server);
    if (entries.length === 0) {
      return 'invalid server';
    }
    for (const entry of entries) {
      if (!this.isValidServerEntry(entry)) {
        return 'invalid server';
      }
    }
    return '';
  }

  private isValidServerEntry(server: string): boolean {
    const raw = server.trim();
    if (!raw) {
      return false;
    }
    if (raw.includes('://')) {
      try {
        const url = new URL(raw);
        const protocol = url.protocol.replace(':', '').toLowerCase();
        if (protocol !== 'ws' && protocol !== 'wss') {
          return false;
        }
        if (!url.hostname || url.username || url.password) {
          return false;
        }
        if (url.port && !this.isValidPort(url.port)) {
          return false;
        }
        return this.isValidHost(this.stripIpv6Brackets(url.hostname));
      } catch {
        return false;
      }
    }
    if (/[/?#]/.test(raw)) {
      return false;
    }
    if (raw.startsWith('[')) {
      const end = raw.indexOf(']');
      if (end <= 1) {
        return false;
      }
      const host = raw.slice(1, end);
      const rest = raw.slice(end + 1);
      if (!this.isIpv6Literal(host)) {
        return false;
      }
      if (!rest) {
        return true;
      }
      if (!rest.startsWith(':')) {
        return false;
      }
      return this.isValidPort(rest.slice(1));
    }
    const colonCount = (raw.match(/:/g) ?? []).length;
    if (colonCount === 0) {
      return this.isValidHost(raw);
    }
    if (colonCount === 1) {
      const idx = raw.lastIndexOf(':');
      const host = raw.slice(0, idx);
      const port = raw.slice(idx + 1);
      if (!this.isValidHost(host)) {
        return false;
      }
      return this.isValidPort(port);
    }
    return this.isIpv6Literal(raw);
  }

  private isValidHost(host: string): boolean {
    const value = host.trim();
    if (!value) {
      return false;
    }
    if (this.isIpv4Literal(value) || this.isIpv6Literal(value)) {
      return true;
    }
    return this.isDomainLike(value);
  }

  private isValidPort(portRaw: string): boolean {
    if (!/^\d+$/.test(portRaw)) {
      return false;
    }
    const port = Number.parseInt(portRaw, 10);
    return Number.isInteger(port) && port > 0 && port <= 65535;
  }

  private isIpv4Literal(value: string): boolean {
    const parts = value.split('.');
    if (parts.length !== 4) {
      return false;
    }
    return parts.every((part) => {
      if (!/^\d+$/.test(part)) {
        return false;
      }
      const number = Number.parseInt(part, 10);
      return number >= 0 && number <= 255;
    });
  }

  private isIpv6Literal(value: string): boolean {
    if (!value || !value.includes(':')) {
      return false;
    }
    try {
      // URL parser handles IPv6 normalization (compressed/expanded forms).
      new URL(`http://[${value}]`);
      return true;
    } catch {
      return false;
    }
  }

  private isDomainLike(value: string): boolean {
    const host = value.toLowerCase();
    if (host === 'localhost') {
      return true;
    }
    if (!/^[a-z0-9.-]+$/.test(host)) {
      return false;
    }
    if (host.startsWith('.') || host.endsWith('.') || host.includes('..')) {
      return false;
    }
    for (const label of host.split('.')) {
      if (!label || label.length > 63) {
        return false;
      }
      if (label.startsWith('-') || label.endsWith('-')) {
        return false;
      }
    }
    return true;
  }

  private handleSessionAdd(arg0?: unknown): string {
    if (typeof arg0 !== 'string') {
      return 'invalid_payload';
    }
    try {
      const parsed = JSON.parse(arg0) as {
        id: string;
        password?: string;
        isFileTransfer?: boolean;
        isViewCamera?: boolean;
        isTerminal?: boolean;
        forceRelay?: boolean;
      };
      const mode: SessionMode = parsed.isFileTransfer
        ? 'file-transfer'
        : parsed.isViewCamera
        ? 'view-camera'
        : parsed.isTerminal
        ? 'terminal'
        : 'remote';
      const forceRelay =
        Boolean(parsed.forceRelay) || this.isForceAlwaysRelayEnabled(parsed.id);
      const peerId = String(parsed.id ?? '').trim();
      const rememberedPassword =
        peerId && (!parsed.password || !String(parsed.password).trim())
          ? this.getPeerOptionValue(peerId, 'password')
          : '';
      const request: ConnectRequest = {
        id: parsed.id,
        password: rememberedPassword || parsed.password,
        mode,
        forceRelay
      };
      this.inputSource1PointerInside = false;
      this.releaseInputSource1PressedKeys();
      this.currentSession?.close();
      this.currentSession = new WebSession(request, this.events);
      if (this.videoSurfaceElementId) {
        this.currentSession.attachVideoSurface(this.videoSurfaceElementId);
      }
      this.store.set('conn_session_id', generateUuid());
      return '';
    } catch (err) {
      this.logger.error('session_add_sync failed', err);
      return 'invalid_payload';
    }
  }

  private async handleSessionStart(arg0?: unknown): Promise<void> {
    if (!this.currentSession) {
      return;
    }
    if (typeof arg0 !== 'string') {
      return;
    }
    const payload = this.safeJson(arg0) as { displays?: unknown } | null;
    const requestedDisplays = Array.isArray(payload?.displays)
      ? payload.displays
          .map((value) => Number(value))
          .filter((value) => Number.isFinite(value) && value >= 0)
      : [];
    const context = this.buildSessionContext();
    this.store.set('session_conn_status', 'connecting');
    this.setServiceStatus('connecting');
    try {
      await this.connectWithCandidates(context);
      if (requestedDisplays.length > 0) {
        this.currentSession.switchDisplay(requestedDisplays);
      }
      this.recordRecentPeer(this.currentSession.getPeerId());
      this.store.set('session_conn_status', 'connected');
      this.setServiceStatus('connected');
    } catch (err) {
      this.store.set('session_conn_status', 'error');
      this.setServiceStatus('error');
      this.logger.error('Session connect failed', err);
      const reason =
        err instanceof Error && err.message
          ? err.message
          : 'Connection failed';
      this.events.emit({
        name: 'toast',
        text: reason
      });
    }
  }

  private async connectWithCandidates(baseContext: SessionContext): Promise<void> {
    const candidates = this.buildConnectionCandidates(baseContext);
    let lastError: unknown;
    for (let i = 0; i < candidates.length; i += 1) {
      const candidate = candidates[i];
      const context: SessionContext = {
        ...baseContext,
        rendezvousServer: candidate.rendezvousServer,
        relayServer: candidate.relayServer
      };
      try {
        await this.currentSession!.connect(context);
        if (i > 0) {
          this.logger.info(
            `Connected via fallback route ${i + 1}/${candidates.length}: ${candidate.rendezvousServer}`
          );
        }
        return;
      } catch (err) {
        lastError = err;
        this.logger.warn(
          `Connect attempt ${i + 1}/${candidates.length} failed via ${candidate.rendezvousServer}`,
          err
        );
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Connection failed');
  }

  private buildConnectionCandidates(baseContext: SessionContext): ConnectionCandidate[] {
    const apiServer = baseContext.apiServer || this.resolveApiServer();
    const rendezvousCandidates = this.getRendezvousCandidatesForConnect(apiServer);
    if (rendezvousCandidates.length === 0) {
      return [
        {
          rendezvousServer: baseContext.rendezvousServer,
          relayServer: baseContext.relayServer
        }
      ];
    }

    const relayInputRaw = this.getOption('relay-server');
    const relayInputList = this.parseServerList(relayInputRaw);
    const rendezvousStart = this.getRoundRobinStart(
      'rendezvous_rr_cursor',
      rendezvousCandidates.length
    );
    const relayStartRaw = this.getRoundRobinStart('relay_rr_cursor', relayInputList.length);
    const relayStart =
      relayInputList.length > 0 && relayInputList.length === rendezvousCandidates.length
        ? rendezvousStart
        : relayStartRaw;

    if (rendezvousCandidates.length > 0) {
      this.store.set(
        'rendezvous_rr_cursor',
        String((rendezvousStart + 1) % rendezvousCandidates.length)
      );
    }
    if (relayInputList.length > 0) {
      this.store.set(
        'relay_rr_cursor',
        String((relayStartRaw + 1) % relayInputList.length)
      );
    }

    const orderedRendezvous: string[] = [];
    for (let i = 0; i < rendezvousCandidates.length; i += 1) {
      orderedRendezvous.push(
        rendezvousCandidates[(rendezvousStart + i) % rendezvousCandidates.length]
      );
    }

    const explicitRelayNormalized = relayInputList
      .map((server) =>
        this.normalizeRelayServer(server, apiServer, orderedRendezvous[0] ?? '')
      )
      .filter((server) => server.length > 0);
    const orderedRelay = explicitRelayNormalized.length
      ? this.rotateList(explicitRelayNormalized, relayStart)
      : [];

    const candidates: ConnectionCandidate[] = [];
    const seen = new Set<string>();
    const attemptCount = Math.max(
      orderedRendezvous.length,
      orderedRelay.length || 0
    );
    for (let i = 0; i < attemptCount; i += 1) {
      const rendezvousServer =
        orderedRendezvous[i % orderedRendezvous.length] || baseContext.rendezvousServer;
      const relayServer = orderedRelay.length
        ? orderedRelay[i % orderedRelay.length]
        : this.deriveRelayServer(rendezvousServer, apiServer);
      if (!rendezvousServer) {
        continue;
      }
      const key = `${rendezvousServer}@@${relayServer}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      candidates.push({ rendezvousServer, relayServer });
    }

    if (candidates.length > 0) {
      return candidates;
    }
    return [
      {
        rendezvousServer: baseContext.rendezvousServer,
        relayServer: baseContext.relayServer
      }
    ];
  }

  private getRendezvousCandidatesForConnect(apiServer: string): string[] {
    const customRaw = this.store.get('option:custom-rendezvous-server', '');
    const customList = this.parseServerList(customRaw);
    const configuredList = this.getConfiguredRendezvousServers();
    const out: string[] = [];
    const pushUnique = (value: string) => {
      if (value && !out.includes(value)) {
        out.push(value);
      }
    };
    for (const item of customList) {
      pushUnique(this.normalizeRendezvousServer(item, apiServer));
    }
    if (out.length > 0) {
      return out;
    }
    for (const item of configuredList) {
      pushUnique(this.normalizeRendezvousServer(item, apiServer));
    }
    return out;
  }

  private getRoundRobinStart(key: string, length: number): number {
    if (length <= 0) {
      return 0;
    }
    const raw = this.store.get(key, '0');
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isInteger(parsed) || parsed < 0) {
      return 0;
    }
    return parsed % length;
  }

  private rotateList<T>(items: T[], start: number): T[] {
    if (items.length <= 1) {
      return [...items];
    }
    const normalizedStart =
      Number.isInteger(start) && start >= 0 ? start % items.length : 0;
    return items.slice(normalizedStart).concat(items.slice(0, normalizedStart));
  }

  private reconnect(): void {
    if (!this.currentSession) {
      return;
    }
    this.logger.info('Reconnect requested');
  }

  private scheduleConnectStatusProbe(delayMs = 400): void {
    if (this.connectStatusDebounceTimer !== undefined) {
      window.clearTimeout(this.connectStatusDebounceTimer);
    }
    this.connectStatusDebounceTimer = window.setTimeout(() => {
      this.connectStatusDebounceTimer = undefined;
      this.startConnectStatusProbe();
    }, delayMs);
  }

  private startConnectStatusProbe(): void {
    if (this.connectStatusDebounceTimer !== undefined) {
      window.clearTimeout(this.connectStatusDebounceTimer);
      this.connectStatusDebounceTimer = undefined;
    }
    if (this.connectStatusTimer !== undefined) {
      window.clearInterval(this.connectStatusTimer);
    }
    void this.refreshConnectStatus();
    this.connectStatusTimer = window.setInterval(() => {
      void this.refreshConnectStatus();
    }, 15000);
  }

  private async refreshConnectStatus(): Promise<void> {
    if (this.connectStatusProbeInFlight) {
      return;
    }
    if (document.visibilityState === 'hidden') {
      return;
    }
    if (this.currentSession) {
      const state = this.currentSession.getState();
      if (state === 'connected' || state === 'connecting') {
        this.setServiceStatus('connected');
        return;
      }
    }
    this.connectStatusProbeInFlight = true;
    try {
      const context = this.buildSessionContext();
      const rendezvousServer =
        this.resolveRendezvousServer() || context.rendezvousServer;
      if (!rendezvousServer) {
        this.setServiceStatus('disconnected');
        return;
      }
      const endpoint = checkWsEndpoint(
        rendezvousServer,
        this.resolveRelayServer(rendezvousServer),
        context.apiServer,
        'rendezvous',
        rendezvousServer,
        context.defaultIdPort
      );
      if (!endpoint) {
        this.setServiceStatus('disconnected');
        return;
      }
      this.setServiceStatus('connecting');
      const reachable = await this.probeWsEndpoint(endpoint, 5000);
      this.setServiceStatus(reachable ? 'connected' : 'error');
    } finally {
      this.connectStatusProbeInFlight = false;
    }
  }

  private async probeWsEndpoint(
    endpoint: string,
    timeoutMs: number
  ): Promise<boolean> {
    return new Promise((resolve) => {
      let done = false;
      let socket: WebSocket;
      try {
        socket = new WebSocket(endpoint);
      } catch {
        resolve(false);
        return;
      }
      const closeAndResolve = (ok: boolean) => {
        if (done) {
          return;
        }
        done = true;
        window.clearTimeout(timer);
        socket.onopen = null;
        socket.onerror = null;
        socket.onclose = null;
        try {
          socket.close();
        } catch {
          // noop
        }
        resolve(ok);
      };
      const timer = window.setTimeout(() => closeAndResolve(false), timeoutMs);
      socket.onopen = () => closeAndResolve(true);
      socket.onerror = () => closeAndResolve(false);
      socket.onclose = () => closeAndResolve(false);
    });
  }

  private setServiceStatus(status: string): void {
    this.store.set('service_status', status);
  }

  private bindCleanupHandlers(): void {
    if (this.cleanupHandlersBound) {
      return;
    }
    this.cleanupHandlersBound = true;
    const cleanup = () => {
      this.closeOnlineQueryTransport();
      this.currentSession?.close();
    };
    window.addEventListener('beforeunload', cleanup);
    window.addEventListener('pagehide', cleanup);
  }

  private ensureMyId(): string {
    const configured = (this.config.profile.id || '').trim();
    if (configured) {
      return configured;
    }
    return this.generateNumericId();
  }

  private ensureFingerprint(): string {
    const current = this.store.get('fingerprint', '');
    if (current) {
      return current;
    }
    const bytes = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    const fingerprint = this.formatFingerprint(bytes);
    this.store.set('fingerprint', fingerprint);
    return fingerprint;
  }

  private formatFingerprint(bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i += 1) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex.replace(/(.{4})/g, '$1 ').trim();
  }

  private generateNumericId(): string {
    const head = this.randomFromAlphabet('123456789', 1);
    const tail = this.randomFromAlphabet('0123456789', 8);
    return `${head}${tail}`;
  }

  private randomFromAlphabet(alphabet: string, length: number): string {
    if (length <= 0 || alphabet.length === 0) {
      return '';
    }
    const bytes = new Uint8Array(length);
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    let output = '';
    for (let i = 0; i < length; i++) {
      output += alphabet[bytes[i] % alphabet.length];
    }
    return output;
  }

  private buildSessionContext(): SessionContext {
    const defaultIdPort = this.getDefaultIdPort();
    const rendezvousServer = this.resolveRendezvousServer();
    const relayServer = this.resolveRelayServer(rendezvousServer);
    const apiServer = this.resolveApiServer();
    const key = this.getOption('key') || this.getEnv('RS_PUB_KEY', 'rs_pub_key');
    const token = this.getOption('access_token') || '';
    const allowDirectIpAccess = this.isOptionEnabled('enable-direct-server');
    const directAccessPort = this.resolveDirectAccessPort();
    const version =
      this.config.version?.trim() ||
      this.getEnv('APP_VERSION', 'app_version') ||
      'web';
    const buildDate = this.config.buildDate?.trim() || '';
    const imageQuality = this.resolveImageQualityPreference();
    const customImageQuality = this.getCustomImageQualityValue();
    const customFps = this.getCustomFpsValue();
    const codecPreference =
      this.getScopedOption('option:session', 'codec-preference') || 'auto';
    const preferI444 = this.getToggleOption('i444');
    return {
      rendezvousServer,
      relayServer,
      defaultIdPort,
      apiServer,
      key,
      token,
      allowDirectIpAccess,
      directAccessPort,
      myId: this.store.get('my_id', this.config.profile.id ?? ''),
      myName: this.store.get('my_name', this.config.profile.name ?? 'Web User'),
      version,
      buildDate,
      platform: 'Web',
      imageQuality,
      customImageQuality,
      customFps,
      codecPreference,
      preferI444
    };
  }

  private isOptionEnabled(key: string): boolean {
    const value = this.getOption(key).trim().toLowerCase();
    return value === 'y' || value === 'yes' || value === '1' || value === 'true';
  }

  private resolveDirectAccessPort(): number {
    const raw = Number.parseInt(this.getOption('direct-access-port') || '', 10);
    if (Number.isInteger(raw) && raw > 0 && raw <= 65535) {
      return raw;
    }
    return this.defaultWsIdPort();
  }

  private getDefaultIdPort(): number {
    const raw = this.getEnv('DEFAULT_ID_PORT', 'default_id_port');
    const parsed = Number.parseInt(raw, 10);
    if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535) {
      return parsed;
    }
    return FALLBACK_DEFAULT_ID_PORT;
  }

  private offsetPort(base: number, delta: number): number {
    const next = base + delta;
    if (next < 1) {
      return 1;
    }
    if (next > 65535) {
      return 65535;
    }
    return next;
  }

  private defaultWsIdPort(): number {
    return this.offsetPort(this.getDefaultIdPort(), 2);
  }

  private getOption(key: string): string {
    const stored = this.store.get(`option:${key}`, '');
    if (stored) {
      return stored;
    }
    return this.optionDefaults.get(key) ?? '';
  }

  private isDebug(): boolean {
    return this.config.env['debug'] === 'true';
  }

  private safeJson(payload: string): Record<string, unknown> {
    try {
      return JSON.parse(payload) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
}
