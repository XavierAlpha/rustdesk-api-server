import 'protobufjs/dist/light/protobuf.min.js';
import messageSchema from '../proto/message.json';
import rendezvousSchema from '../proto/rendezvous.json';

type ProtoTypeLike = {
  encode(payload: unknown): { finish(): Uint8Array };
  decode(payload: Uint8Array): unknown;
  toObject(
    message: unknown,
    options?: Record<string, unknown>
  ): Record<string, unknown>;
};

type ProtoRootLike = {
  lookupType(name: string): ProtoTypeLike;
};

type ProtobufRuntime = {
  Root: {
    fromJSON(schema: unknown): ProtoRootLike;
  };
};

export type ProtoRoots = {
  message: ProtoRootLike;
  rendezvous: ProtoRootLike;
  messageType: ProtoTypeLike;
  rendezvousType: ProtoTypeLike;
  idPkType: ProtoTypeLike;
};

type DecodedWithToObject = {
  toObject?: (options?: Record<string, unknown>) => Record<string, unknown>;
};

function getProtobufRuntime(): ProtobufRuntime {
  const runtime = (
    globalThis as typeof globalThis & { protobuf?: ProtobufRuntime }
  ).protobuf;
  if (!runtime?.Root?.fromJSON) {
    throw new Error('protobufjs runtime is unavailable in web bridge');
  }
  return runtime;
}

export async function loadProtos(): Promise<ProtoRoots> {
  const protobuf = getProtobufRuntime();
  const messageRoot = protobuf.Root.fromJSON(messageSchema);
  const rendezvousRoot = protobuf.Root.fromJSON(rendezvousSchema);
  const messageType = messageRoot.lookupType('hbb.Message');
  const rendezvousType = rendezvousRoot.lookupType('hbb.RendezvousMessage');
  const idPkType = messageRoot.lookupType('hbb.IdPk');
  return {
    message: messageRoot,
    rendezvous: rendezvousRoot,
    messageType,
    rendezvousType,
    idPkType
  };
}

export function decodeProtoObject<T extends Record<string, unknown>>(
  type: ProtoTypeLike,
  data: Uint8Array,
  options?: Record<string, unknown>
): T {
  const decoded = type.decode(data) as DecodedWithToObject;
  if (typeof decoded.toObject === 'function') {
    return decoded.toObject(options) as T;
  }
  return type.toObject(decoded, options) as T;
}
