import nacl from 'tweetnacl';

const localSecretEncoder = new TextEncoder();
const localSecretDecoder = new TextDecoder();
const LOCAL_SECRET_PREFIX = 'enc00:';
const LOCAL_SECRET_CONTEXT = 'camellia.web.local-secret';

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

export function decodeBase64(input: string): Uint8Array {
  const normalized = input.replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (normalized.length === 0) {
    return new Uint8Array();
  }
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function encodeBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i += 1) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

function deriveLocalSecretKey(seed: string): Uint8Array {
  const stableSeed = `${LOCAL_SECRET_CONTEXT}:${String(seed ?? '')}`;
  const digest = nacl.hash(localSecretEncoder.encode(stableSeed));
  return digest.slice(0, nacl.secretbox.keyLength);
}

export function isLocalSecretEncrypted(value: string): boolean {
  return String(value ?? '').startsWith(LOCAL_SECRET_PREFIX);
}

export function encryptLocalSecret(value: string, seed: string): string {
  const plain = String(value ?? '');
  if (!plain) {
    return '';
  }
  const key = deriveLocalSecretKey(seed);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const payload = localSecretEncoder.encode(plain);
  const sealed = nacl.secretbox(payload, nonce, key);
  const packed = new Uint8Array(nonce.length + sealed.length);
  packed.set(nonce, 0);
  packed.set(sealed, nonce.length);
  return `${LOCAL_SECRET_PREFIX}${encodeBase64(packed)}`;
}

export function decryptLocalSecret(value: string, seed: string): string | null {
  const raw = String(value ?? '');
  if (!raw) {
    return '';
  }
  if (!isLocalSecretEncrypted(raw)) {
    return null;
  }
  try {
    const payload = decodeBase64(raw.slice(LOCAL_SECRET_PREFIX.length));
    if (payload.length <= nacl.secretbox.nonceLength) {
      return null;
    }
    const nonce = payload.slice(0, nacl.secretbox.nonceLength);
    const sealed = payload.slice(nacl.secretbox.nonceLength);
    const key = deriveLocalSecretKey(seed);
    const opened = nacl.secretbox.open(sealed, nonce, key);
    if (!opened) {
      return null;
    }
    return localSecretDecoder.decode(opened);
  } catch {
    return null;
  }
}

export function signOpen(signed: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const opened = nacl.sign.open(signed, publicKey);
  if (!opened) {
    throw new CryptoError('Signature verification failed');
  }
  return opened;
}

export function createSymmetricKey(theirPublicKey: Uint8Array): {
  publicKey: Uint8Array;
  symmetricKey: Uint8Array;
  sealed: Uint8Array;
} {
  if (theirPublicKey.length !== nacl.box.publicKeyLength) {
    throw new CryptoError(`Invalid peer public key length: ${theirPublicKey.length}`);
  }
  const keyPair = nacl.box.keyPair();
  const symmetricKey = nacl.randomBytes(nacl.secretbox.keyLength);
  const nonce = new Uint8Array(nacl.box.nonceLength);
  const sealed = nacl.box(symmetricKey, nonce, theirPublicKey, keyPair.secretKey);
  return { publicKey: keyPair.publicKey, symmetricKey, sealed };
}

export function decodeSymmetricKey(
  sealed: Uint8Array,
  theirPublicKey: Uint8Array,
  ourSecretKey: Uint8Array
): Uint8Array {
  if (theirPublicKey.length !== nacl.box.publicKeyLength) {
    throw new CryptoError(`Invalid peer public key length: ${theirPublicKey.length}`);
  }
  const nonce = new Uint8Array(nacl.box.nonceLength);
  const opened = nacl.box.open(sealed, nonce, theirPublicKey, ourSecretKey);
  if (!opened) {
    throw new CryptoError('Failed to decrypt symmetric key');
  }
  if (opened.length !== nacl.secretbox.keyLength) {
    throw new CryptoError(`Invalid symmetric key length: ${opened.length}`);
  }
  return opened;
}

export class SecretBoxCipher {
  private readonly key: Uint8Array;
  private sendSeq = 0;
  private recvSeq = 0;

  constructor(key: Uint8Array) {
    if (key.length !== nacl.secretbox.keyLength) {
      throw new CryptoError(`Invalid secretbox key length: ${key.length}`);
    }
    this.key = key;
  }

  encrypt(payload: Uint8Array): Uint8Array {
    this.sendSeq += 1;
    const nonce = this.makeNonce(this.sendSeq);
    return nacl.secretbox(payload, nonce, this.key);
  }

  decrypt(payload: Uint8Array): Uint8Array {
    if (payload.length <= 1) {
      return payload;
    }
    this.recvSeq += 1;
    const nonce = this.makeNonce(this.recvSeq);
    const opened = nacl.secretbox.open(payload, nonce, this.key);
    if (!opened) {
      throw new CryptoError('Secretbox decryption failed');
    }
    return opened;
  }

  private makeNonce(seq: number): Uint8Array {
    const nonce = new Uint8Array(nacl.secretbox.nonceLength);
    let value = seq;
    for (let i = 0; i < 8; i += 1) {
      nonce[i] = value & 0xff;
      value = Math.floor(value / 256);
    }
    return nonce;
  }
}
