export type CamelliaConfig = {
  appName?: string;
  version?: string;
  buildDate?: string;
  apiServer?: string;
  isPublicServer?: boolean;
  rendezvousServers?: string[];
  relayServers?: string[];
  env?: Record<string, string>;
  profile?: {
    name?: string;
    id?: string;
  };
  langs?: unknown;
};

export type RuntimeConfig = Required<
  Pick<
    CamelliaConfig,
    'appName' | 'version' | 'buildDate' | 'apiServer' | 'isPublicServer'
  >
> & {
  rendezvousServers: string[];
  relayServers: string[];
  env: Record<string, string>;
  profile: { name: string; id: string };
  langs: unknown;
};

const defaultConfig: RuntimeConfig = {
  appName: 'Camellia',
  version: '',
  buildDate: '',
  apiServer: '',
  isPublicServer: true,
  rendezvousServers: [],
  relayServers: [],
  env: {},
  profile: { name: 'Web User', id: '' },
  langs: []
};

export function loadConfig(): RuntimeConfig {
  const input = (window.__CAMELLIA_WEB__ ?? {}) as CamelliaConfig;
  return {
    ...defaultConfig,
    ...input,
    env: { ...defaultConfig.env, ...(input.env ?? {}) },
    profile: {
      ...defaultConfig.profile,
      ...(input.profile ?? {})
    },
    rendezvousServers: [...(input.rendezvousServers ?? [])],
    relayServers: [...(input.relayServers ?? [])]
  };
}
