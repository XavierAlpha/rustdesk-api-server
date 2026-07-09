import { Logger } from '../core/logger';
import { RuntimeConfig } from '../core/config';
import { generateUuid } from '../core/uuid';
import { SecretBoxCipher, createSymmetricKey, decodeBase64, signOpen } from './crypto';
import { MessageInbox } from './inbox';
import { decodeProtoObject, ProtoRoots } from './proto';
import { WebSocketTransport } from './transport';

export type RelayInfo = {
  relayServer: string;
  relayEndpoint: string;
  uuid: string;
  signedIdPk: Uint8Array;
};

export type DirectInfo = {
  endpoint: string;
  signedIdPk: Uint8Array;
};

export type ConnectionRoute =
  | { kind: 'direct'; direct: DirectInfo }
  | { kind: 'relay'; relay: RelayInfo };

export type RendezvousOptions = {
  peerId: string;
  relayServer: string;
  rendezvousServer: string;
  defaultIdPort: number;
  apiServer: string;
  token?: string;
  key?: string;
  connType: number;
  secure: boolean;
  forceRelay?: boolean;
  version?: string;
};

const DIRECT_PROBE_ATTEMPTS = 1;
const DIRECT_PROBE_TIMEOUT_MS = 1200;
type RouteKind = 'auto' | 'rendezvous' | 'relay';
const FATAL_DIRECT_FAILURES = new Set([
  'ID does not exist',
  'Remote desktop is offline',
  'Key mismatch',
  'Key overuse'
]);

export class RendezvousClient {
  private readonly logger: Logger;
  private readonly proto: ProtoRoots;

  constructor(_config: RuntimeConfig, proto: ProtoRoots, logger?: Logger) {
    this.proto = proto;
    this.logger = logger ?? new Logger('rendezvous');
  }

  async requestConnectionRoute(options: RendezvousOptions): Promise<ConnectionRoute> {
    this.logger.info(
      `Selecting route: peer=${options.peerId}, forceRelay=${Boolean(options.forceRelay)}`
    );
    if (options.forceRelay) {
      this.logger.info('Force relay enabled; skipping direct probe.');
      const relay = await this.requestRelay(options);
      return { kind: 'relay', relay };
    }
    let directProbe: { direct?: DirectInfo; relay?: RelayInfo } | null = null;
    try {
      directProbe = await this.requestDirect(options);
    } catch (err) {
      if (isFatalDirectError(err)) {
        throw err;
      }
      this.logger.warn('Direct connection probe failed', err);
    }
    if (directProbe?.direct) {
      this.logger.info(`Direct route available: ${directProbe.direct.endpoint}`);
    }
    if (directProbe?.relay) {
      this.logger.info(
        `Relay route suggested by rendezvous: ${directProbe.relay.relayEndpoint}`
      );
    }
    if (directProbe?.direct) {
      return { kind: 'direct', direct: directProbe.direct };
    }
    if (directProbe?.relay) {
      return { kind: 'relay', relay: directProbe.relay };
    }
    this.logger.info('Direct route unavailable; requesting relay from rendezvous server.');
    const relay = await this.requestRelay(options);
    return { kind: 'relay', relay };
  }

  async requestRelay(options: RendezvousOptions): Promise<RelayInfo> {
    const endpoint = checkWsEndpoint(
      options.rendezvousServer,
      options.relayServer,
      options.apiServer,
      'rendezvous',
      options.rendezvousServer,
      options.defaultIdPort
    );
    if (!endpoint) {
      throw new Error('Rendezvous server not configured');
    }
    this.logger.info(`Requesting relay via ${endpoint}`);
    const transport = new WebSocketTransport('rendezvous');
    await transport.connect(endpoint);
    const inbox = new MessageInbox(transport);
    try {
      await this.secureIfNeeded(transport, inbox, options.key ?? '', endpoint);

      const uuid = generateUuid();
      const requestRelay = {
        id: options.peerId,
        uuid,
        // Normalize relay hint to host:port for native peers while web keeps ws/wss locally.
        relayServer: toPeerRelayServerHint(
          options.relayServer,
          options.rendezvousServer,
          options.defaultIdPort
        ),
        secure: options.secure,
        connType: options.connType,
        licenceKey: options.key ?? '',
        token: options.token ?? ''
      };
      const payload = this.proto.rendezvousType.encode({ requestRelay }).finish();
      transport.send(payload);

      for (;;) {
        const data = await inbox.next(15000);
        const msg = decodeProtoObject<Record<string, unknown>>(
          this.proto.rendezvousType,
          data,
          {
            longs: String,
            bytes: Uint8Array,
            defaults: false
          }
        );
        const relayResponse = msg.relayResponse as
          | {
              relayServer?: string;
              uuid?: string;
              pk?: Uint8Array;
              refuseReason?: string;
              id?: string;
              version?: string;
            }
          | undefined;
        if (relayResponse) {
          if (relayResponse.refuseReason) {
            throw new Error(relayResponse.refuseReason);
          }
          const pkLen = relayResponse.pk?.length ?? 0;
          const relayId = relayResponse.id ?? '';
          const relayVersion = relayResponse.version ?? '';
          this.logger.info(
            `Relay response details: pk_len=${pkLen}, id=${relayId || '-'}, version=${relayVersion || '-'}`
          );
          if (!relayResponse.pk || relayResponse.pk.length === 0) {
            throw new Error(
              'Relay response missing signed peer identity. Ensure the target can send RelayResponse.id and the ID server has RS_PRIV_KEY matching your RS_PUB_KEY.'
            );
          }
          const relayServer = selectWebRelayServer(
            options.relayServer,
            relayResponse.relayServer
          );
          const relayEndpoint = checkWsEndpoint(
            relayServer,
            relayServer,
            options.apiServer,
            'relay',
            options.rendezvousServer,
            options.defaultIdPort
          );
          this.logger.info(`Relay response received: ${relayEndpoint}`);
          return {
            relayServer,
            relayEndpoint,
            uuid: relayResponse.uuid ?? uuid,
            signedIdPk: relayResponse.pk ?? new Uint8Array()
          };
        }
      }
    } catch (err) {
      if (isTimeoutError(err)) {
        throw new Error(
          `Timeout waiting for relay response from ${endpoint}. ` +
            'Check the target is online and the ID/Relay server matches your other clients.'
        );
      }
      throw err;
    } finally {
      inbox.close();
      transport.close();
    }
  }

  private async requestDirect(
    options: RendezvousOptions
  ): Promise<{ direct?: DirectInfo; relay?: RelayInfo } | null> {
    const endpoint = checkWsEndpoint(
      options.rendezvousServer,
      options.relayServer,
      options.apiServer,
      'rendezvous',
      options.rendezvousServer,
      options.defaultIdPort
    );
    if (!endpoint) {
      return null;
    }
    const transport = new WebSocketTransport('rendezvous:direct');
    const inbox = new MessageInbox(transport);
    try {
      await transport.connect(endpoint);
      await this.secureIfNeeded(transport, inbox, options.key ?? '', endpoint);
      for (let attempt = 1; attempt <= DIRECT_PROBE_ATTEMPTS; attempt++) {
        const punchHoleRequest = {
          id: options.peerId,
          natType: 0,
          licenceKey: options.key ?? '',
          connType: options.connType,
          token: options.token ?? '',
          version: options.version ?? '',
          udpPort: 0,
          forceRelay: Boolean(options.forceRelay)
        };
        const request = this.proto.rendezvousType
          .encode({ punchHoleRequest })
          .finish();
        transport.send(request);
        let msg: Record<string, unknown>;
        try {
          msg = await this.nextRendezvousMessage(
            inbox,
            DIRECT_PROBE_TIMEOUT_MS
          );
        } catch {
          continue;
        }
        const relay = this.parseRelayResponse(msg, options);
        if (relay) {
          return { relay };
        }
        const punch = msg.punchHoleResponse as
          | {
              socketAddr?: Uint8Array;
              pk?: Uint8Array;
              relayServer?: string;
              isUdp?: boolean;
              failure?: number | string;
              otherFailure?: string;
            }
          | undefined;
        if (!punch) {
          continue;
        }
        if (punch.isUdp) {
          continue;
        }
        if (punch.otherFailure) {
          throw new Error(punch.otherFailure);
        }
        const socketAddr = punch.socketAddr;
        if (!socketAddr || socketAddr.length === 0) {
          const reason = this.parsePunchHoleFailure(punch.failure);
          if (reason !== 'Punch hole failed') {
            throw new Error(reason);
          }
          this.logger.warn('Direct punch hole failed; falling back to relay');
          return null;
        }
        const peerAddress = decodeAddrMangle(socketAddr);
        if (!peerAddress) {
          continue;
        }
        const relayServer = selectWebRelayServer(options.relayServer, punch.relayServer);
        const endpoint = checkWsEndpoint(
          peerAddress,
          relayServer,
          options.apiServer,
          'auto',
          options.rendezvousServer,
          options.defaultIdPort
        );
        if (!endpoint) {
          continue;
        }
        return {
          direct: {
            endpoint,
            signedIdPk: punch.pk ?? new Uint8Array()
          }
        };
      }
      return null;
    } finally {
      inbox.close();
      transport.close();
    }
  }

  private decodeRendezvousMessage(data: Uint8Array): Record<string, unknown> {
    return decodeProtoObject<Record<string, unknown>>(
      this.proto.rendezvousType,
      data,
      {
        longs: String,
        bytes: Uint8Array,
        defaults: false
      }
    );
  }

  private async nextRendezvousMessage(
    inbox: MessageInbox,
    timeoutMs: number
  ): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error('timeout waiting for message');
      }
      const msg = this.decodeRendezvousMessage(await inbox.next(remaining));
      if (msg.keyExchange) {
        this.logger.debug('Ignoring rendezvous key exchange control frame');
        continue;
      }
      return msg;
    }
  }

  private parseRelayResponse(
    msg: Record<string, unknown>,
    options: RendezvousOptions
  ): RelayInfo | null {
    const relayResponse = msg.relayResponse as
      | {
          relayServer?: string;
          uuid?: string;
          pk?: Uint8Array;
          refuseReason?: string;
          id?: string;
          version?: string;
        }
      | undefined;
    if (!relayResponse) {
      return null;
    }
    if (relayResponse.refuseReason) {
      throw new Error(relayResponse.refuseReason);
    }
    const pkLen = relayResponse.pk?.length ?? 0;
    const relayId = relayResponse.id ?? '';
    const relayVersion = relayResponse.version ?? '';
    this.logger.info(
      `Relay response details: pk_len=${pkLen}, id=${relayId || '-'}, version=${relayVersion || '-'}`
    );
    const relayServer = selectWebRelayServer(options.relayServer, relayResponse.relayServer);
    if (!relayResponse.pk || relayResponse.pk.length === 0) {
      throw new Error(
        'Relay response missing signed peer identity. Ensure the target can send RelayResponse.id and the ID server has RS_PRIV_KEY matching your RS_PUB_KEY.'
      );
    }
    return {
      relayServer,
      relayEndpoint: checkWsEndpoint(
        relayServer,
        relayServer,
        options.apiServer,
        'relay',
        options.rendezvousServer,
        options.defaultIdPort
      ),
      uuid: relayResponse.uuid ?? generateUuid(),
      signedIdPk: relayResponse.pk ?? new Uint8Array()
    };
  }

  private parsePunchHoleFailure(failure: number | string | undefined): string {
    if (typeof failure === 'string' && failure.length > 0) {
      return failure;
    }
    switch (failure) {
      case 0:
        return 'ID does not exist';
      case 2:
        return 'Remote desktop is offline';
      case 3:
        return 'Key mismatch';
      case 4:
        return 'Key overuse';
      default:
        return 'Punch hole failed';
    }
  }

  private async secureIfNeeded(
    transport: WebSocketTransport,
    inbox: MessageInbox,
    key: string,
    endpoint: string
  ): Promise<void> {
    if (endpoint.startsWith('wss://')) {
      return;
    }
    if (!key) {
      this.logger.warn('No rendezvous public key configured; skipping secure handshake');
      return;
    }
    const rsPk = decodeBase64(key);
    try {
      const data = await inbox.next(8000);
      const msg = decodeProtoObject<Record<string, unknown>>(
        this.proto.rendezvousType,
        data,
        {
          longs: String,
          bytes: Uint8Array,
          defaults: false
        }
      );
      const keyExchange = msg.keyExchange as { keys?: Uint8Array[] } | undefined;
      if (!keyExchange || !keyExchange.keys || keyExchange.keys.length !== 1) {
        inbox.pushFront(data);
        return;
      }
      const signedKey = keyExchange.keys[0];
      const theirPk = signOpen(signedKey, rsPk);
      const { publicKey, symmetricKey, sealed } = createSymmetricKey(theirPk);
      const reply = this.proto.rendezvousType.encode({
        keyExchange: { keys: [publicKey, sealed] }
      }).finish();
      transport.send(reply);
      transport.setCipher(new SecretBoxCipher(symmetricKey));
      this.logger.info('Rendezvous secure channel established');
    } catch (err) {
      this.logger.warn('Secure rendezvous handshake failed', err);
    }
  }
}

export function checkWsEndpoint(
  endpoint: string,
  relayServer: string,
  apiServer: string,
  routeKind: RouteKind = 'auto',
  rendezvousServer = '',
  defaultIdPort: number
): string {
  if (!endpoint) {
    return '';
  }
  const raw = endpoint.trim();
  if (!raw) {
    return '';
  }
  if (raw.startsWith('ws://') || raw.startsWith('wss://')) {
    try {
      const url = new URL(raw);
      const host = formatHostForUrl(url.hostname, url.hostname.includes(':'));
      const hasExplicitPath = Boolean(url.pathname && url.pathname !== '/');
      const explicitPortFromRaw = parseExplicitPortFromUrlInput(raw);
      const explicitPort = url.port
        ? Number.parseInt(url.port, 10)
        : explicitPortFromRaw;
      const baseIdPort = normalizeDefaultIdPort(defaultIdPort);
      const defaultWsIdPort = offsetPort(baseIdPort, 2);
      const defaultWsRelayPort = offsetPort(baseIdPort, 3);
      if (url.protocol === 'ws:') {
        const defaultPort = routeKind === 'relay' ? defaultWsRelayPort : defaultWsIdPort;
        const port = explicitPort ?? defaultPort;
        const path = hasExplicitPath ? url.pathname : '';
        const query = url.search ?? '';
        return `ws://${host}:${port}${path}${query}`;
      }
      const defaultWssPort = routeKind === 'relay' ? defaultWsRelayPort : defaultWsIdPort;
      const port = explicitPort ?? defaultWssPort;
      const path = hasExplicitPath ? url.pathname : (routeKind === 'relay' ? '/ws/relay' : '/ws/id');
      const query = url.search ?? '';
      return `wss://${host}:${port}${path}${query}`;
    } catch {
      return raw;
    }
  }

  const parsed = parseServerEndpoint(raw);
  if (!parsed) {
    return raw;
  }
  const baseIdPort = normalizeDefaultIdPort(defaultIdPort);
  const defaultServiceRelayPort = offsetPort(baseIdPort, 1);

  const relayParsed = parseServerEndpoint(relayServer.trim());
  const rendezvousParsed = parseServerEndpoint(rendezvousServer.trim());
  const nativePort = (
    value: ParsedServerEndpoint | null,
    fallback: number
  ): number => {
    if (!value) {
      return fallback;
    }
    const port = value.port ?? fallback;
    if (value.scheme === 'ws' || value.scheme === 'wss') {
      return offsetPort(port, -2);
    }
    return port;
  };
  const rendezvousPort = nativePort(rendezvousParsed, baseIdPort);
  const relayPort = nativePort(relayParsed, defaultServiceRelayPort);
  const endpointPort =
    parsed.port ?? (routeKind === 'relay' ? relayPort : rendezvousPort);

  let relay = routeKind === 'relay';
  if (routeKind === 'auto') {
    if (endpointPort === rendezvousPort) {
      relay = false;
    } else if (endpointPort === rendezvousPort - 1) {
      relay = false;
    } else if (endpointPort === relayPort || endpointPort === rendezvousPort + 1) {
      relay = true;
    } else {
      relay = true;
    }
  }

  let dstPort = endpointPort + 2;
  if (!relay && endpointPort === rendezvousPort - 1) {
    dstPort = endpointPort + 3;
  }

  if (parsed.isIp) {
    return `ws://${formatHostForUrl(parsed.host, parsed.isIpv6)}:${dstPort}`;
  }

  const protocol = resolveDomainProtocol(apiServer);
  const path = relay ? '/ws/relay' : '/ws/id';
  return `${protocol}://${formatHostForUrl(parsed.host, parsed.isIpv6)}:${dstPort}${path}`;
}

function normalizeDefaultIdPort(value: number): number {
  if (!Number.isFinite(value)) {
    return 1;
  }
  return offsetPort(Math.trunc(value), 0);
}

function offsetPort(base: number, delta: number): number {
  const next = base + delta;
  if (next < 1) {
    return 1;
  }
  if (next > 65535) {
    return 65535;
  }
  return next;
}

type ParsedServerEndpoint = {
  scheme: 'ws' | 'wss' | null;
  host: string;
  port: number | null;
  isIpv6: boolean;
  isIp: boolean;
};

function parseServerEndpoint(endpoint: string): ParsedServerEndpoint | null {
  if (!endpoint) {
    return null;
  }
  const trimmed = endpoint.trim();
  if (!trimmed) {
    return null;
  }
  if (
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed.startsWith('ws://') ||
    trimmed.startsWith('wss://')
  ) {
    try {
      const url = new URL(trimmed);
      const host = url.hostname;
      if (!host) {
        return null;
      }
      const isIpv6 = host.includes(':');
      const explicitPortFromRaw = parseExplicitPortFromUrlInput(trimmed);
      const portText = url.port;
      if (portText) {
        const port = Number(portText);
        if (!Number.isInteger(port) || port <= 0 || port > 65535) {
          return null;
        }
        return {
          scheme: url.protocol === 'wss:' ? 'wss' : 'ws',
          host,
          port,
          isIpv6,
          isIp: isIpv4Address(host) || isIpv6
        };
      }
      if (explicitPortFromRaw !== null) {
        return {
          scheme: url.protocol === 'wss:' ? 'wss' : 'ws',
          host,
          port: explicitPortFromRaw,
          isIpv6,
          isIp: isIpv4Address(host) || isIpv6
        };
      }
      return {
        scheme: url.protocol === 'wss:' ? 'wss' : 'ws',
        host,
        port: null,
        isIpv6,
        isIp: isIpv4Address(host) || isIpv6
      };
    } catch {
      return null;
    }
  }

  let hostPart = trimmed;
  const pathStart = hostPart.search(/[/?#]/);
  if (pathStart >= 0) {
    hostPart = hostPart.slice(0, pathStart);
  }
  hostPart = hostPart.trim();
  if (!hostPart) {
    return null;
  }

  if (hostPart.startsWith('[')) {
    const end = hostPart.indexOf(']');
    if (end === -1) {
      return null;
    }
    const host = hostPart.slice(1, end);
    const rest = hostPart.slice(end + 1);
    if (!rest) {
      return { scheme: null, host, port: null, isIpv6: true, isIp: true };
    }
    if (!rest.startsWith(':')) {
      return null;
    }
    const port = Number.parseInt(rest.slice(1), 10);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      return null;
    }
    return { scheme: null, host, port, isIpv6: true, isIp: true };
  }

  const firstColon = hostPart.indexOf(':');
  const lastColon = hostPart.lastIndexOf(':');
  if (firstColon !== -1 && firstColon === lastColon) {
    const host = hostPart.slice(0, firstColon);
    const port = Number.parseInt(hostPart.slice(firstColon + 1), 10);
    if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
      return null;
    }
    return { scheme: null, host, port, isIpv6: false, isIp: isIpv4Address(host) };
  }
  if (firstColon === -1) {
    return {
      scheme: null,
      host: hostPart,
      port: null,
      isIpv6: false,
      isIp: isIpv4Address(hostPart)
    };
  }
  return { scheme: null, host: hostPart, port: null, isIpv6: true, isIp: true };
}

function parseExplicitPortFromUrlInput(raw: string): number | null {
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
    const port = Number.parseInt(rest.slice(1), 10);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      return null;
    }
    return port;
  }
  const firstColon = authority.indexOf(':');
  const lastColon = authority.lastIndexOf(':');
  if (firstColon < 0 || firstColon !== lastColon) {
    return null;
  }
  const port = Number.parseInt(authority.slice(lastColon + 1), 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return null;
  }
  return port;
}

function resolveDomainProtocol(apiServer: string): 'ws' | 'wss' {
  if (apiServer.trim().toLowerCase().startsWith('https')) {
    return 'wss';
  }
  return 'ws';
}

function toPeerRelayServerHint(
  relayServer: string,
  rendezvousServer: string,
  defaultIdPort: number
): string {
  const rendezvousRaw = rendezvousServer.trim();
  const relayRaw = relayServer.trim();
  const rendezvous = parseServerEndpoint(rendezvousRaw);
  const relay = parseServerEndpoint(relayRaw);
  if (!rendezvous && !relay) {
    return '';
  }

  const defaultBasePort = normalizeDefaultIdPort(defaultIdPort);
  const pageIsHttps =
    typeof window !== 'undefined' && window.location?.protocol === 'https:';
  const isWssReverseProxy = rendezvous?.scheme === 'wss' && pageIsHttps;

  // Reverse-proxy entry (wss over https): always map hint to DEFAULT_ID_PORT + 1.
  if (isWssReverseProxy && rendezvous) {
    return `${formatHostForUrl(rendezvous.host, rendezvous.isIpv6)}:${offsetPort(defaultBasePort, 1)}`;
  }

  const idBasePort = rendezvous
    ? rendezvous.scheme === 'ws' || rendezvous.scheme === 'wss'
      ? offsetPort(rendezvous.port ?? offsetPort(defaultBasePort, 2), -2)
      : (rendezvous.port ?? defaultBasePort)
    : defaultBasePort;

  // Non-reverse-proxy path: explicit relay host/port wins, otherwise derive from ID base.
  if (
    relay &&
    !relayRaw.startsWith('http://') &&
    !relayRaw.startsWith('https://')
  ) {
    const relayNativePort = relay.port
      ? relay.scheme === 'ws' || relay.scheme === 'wss'
        ? offsetPort(relay.port, -2)
        : relay.port
      : offsetPort(idBasePort, 1);
    return `${formatHostForUrl(relay.host, relay.isIpv6)}:${relayNativePort}`;
  }

  if (!rendezvous) {
    return '';
  }
  return `${formatHostForUrl(rendezvous.host, rendezvous.isIpv6)}:${offsetPort(idBasePort, 1)}`;
}

function selectWebRelayServer(preferred: string, fallback?: string): string {
  const primary = preferred.trim();
  if (primary) {
    return primary;
  }
  return String(fallback ?? '').trim();
}

function formatHostForUrl(host: string, isIpv6: boolean): string {
  if (!isIpv6) {
    return host;
  }
  if (host.startsWith('[') && host.endsWith(']')) {
    return host;
  }
  return `[${host}]`;
}

function isIpv4Address(value: string): boolean {
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

function isFatalDirectError(err: unknown): boolean {
  const message =
    err instanceof Error
      ? err.message
      : typeof err === 'string'
        ? err
        : '';
  return FATAL_DIRECT_FAILURES.has(message);
}

function isTimeoutError(err: unknown): boolean {
  if (!err) {
    return false;
  }
  const message =
    err instanceof Error
      ? err.message
      : typeof err === 'string'
        ? err
        : '';
  return message.toLowerCase().includes('timeout');
}

function decodeAddrMangle(bytes: Uint8Array): string | null {
  if (!bytes || bytes.length === 0) {
    return null;
  }
  if (bytes.length > 16) {
    if (bytes.length !== 18) {
      return null;
    }
    const port = Number(bytes[16]) | (Number(bytes[17]) << 8);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      return null;
    }
    const host = ipv6BytesToString(bytes.subarray(0, 16));
    return `[${host}]:${port}`;
  }
  const padded = new Uint8Array(16);
  padded.set(bytes);
  let value = BigInt(0);
  const shift8 = BigInt(8);
  const shift17 = BigInt(17);
  const shift49 = BigInt(49);
  const maskTm = BigInt('0xffffffff');
  const maskIp = BigInt('0xffffffff');
  const maskPortWide = BigInt('0xffffff');
  const maskPortNarrow = BigInt('0xffff');
  const maskByte = BigInt('0xff');
  const maxPort = BigInt(65535);
  for (let i = 15; i >= 0; i--) {
    value = (value << shift8) | BigInt(padded[i]);
  }
  const tm = (value >> shift17) & maskTm;
  const ipRaw = ((value >> shift49) - tm) & maskIp;
  const portRaw = (value & maskPortWide) - (tm & maskPortNarrow);
  if (portRaw <= BigInt(0) || portRaw > maxPort) {
    return null;
  }
  const b0 = Number(ipRaw & maskByte);
  const b1 = Number((ipRaw >> shift8) & maskByte);
  const b2 = Number((ipRaw >> BigInt(16)) & maskByte);
  const b3 = Number((ipRaw >> BigInt(24)) & maskByte);
  return `${b0}.${b1}.${b2}.${b3}:${Number(portRaw)}`;
}

function ipv6BytesToString(bytes: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const value = (Number(bytes[i]) << 8) | Number(bytes[i + 1]);
    groups.push(value.toString(16));
  }
  return groups.join(':');
}
