import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';

import type { LoginDeviceByIp, TapoDeviceSession } from './client.js';

const AES_CIPHER_ALGORITHM = 'aes-128-cbc';
const HANDSHAKE_HEADERS = {
  'Content-Type': 'application/octet-stream',
  'Accept': 'application/octet-stream',
  'User-Agent': 'Tapo',
  'Connection': 'keep-alive',
};

type AxiosResponseLike = {
  status: number;
  data: unknown;
  headers: Record<string, unknown>;
};

type AxiosLike = {
  post: (url: string, data?: unknown, config?: Record<string, unknown>) => Promise<AxiosResponseLike>;
  (config: Record<string, unknown>): Promise<AxiosResponseLike>;
};

type TapoDeviceFactory = (options: { send: (request: unknown) => Promise<unknown> }) => TapoDeviceSession;
type CheckError = (payload: unknown) => void;

const loadAxios = async (): Promise<AxiosLike> => {
  const axiosModule = await import('axios');
  return (axiosModule.default ?? axiosModule) as unknown as AxiosLike;
};

const loadTapoDeviceFactory = async (): Promise<TapoDeviceFactory> => {
  const module = await import('tp-link-tapo-connect/dist/tapo-device.js');
  const factory = (module as { TapoDevice?: TapoDeviceFactory }).TapoDevice;
  if (typeof factory !== 'function') {
    throw new Error('tp-link-tapo-connect did not provide TapoDevice');
  }
  return factory;
};

const loadCheckError = async (): Promise<CheckError> => {
  const module = await import('tp-link-tapo-connect/dist/tapo-utils.js');
  const checker = (module as { checkError?: CheckError }).checkError;
  if (typeof checker !== 'function') {
    throw new Error('tp-link-tapo-connect did not provide checkError');
  }
  return checker;
};

const readHeader = (headers: Record<string, unknown>, header: string): string | undefined => {
  const value = headers[header] ?? headers[header.toLowerCase()];
  if (Array.isArray(value)) {
    return value[0];
  }
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
};

const toBuffer = (payload: unknown): Buffer => {
  if (Buffer.isBuffer(payload)) {
    return payload;
  }
  if (payload instanceof ArrayBuffer) {
    return Buffer.from(payload);
  }
  if (ArrayBuffer.isView(payload)) {
    return Buffer.from(payload.buffer, payload.byteOffset, payload.byteLength);
  }
  return Buffer.from(String(payload));
};

const createPreview = (payload: unknown, contentType: string): string | undefined => {
  if (!/text|json|html/i.test(contentType)) {
    return undefined;
  }
  const text = toBuffer(payload).toString('utf8');
  const sanitized = text.replace(/[^\x20-\x7E]+/g, ' ').trim();
  if (!sanitized) {
    return undefined;
  }
  return sanitized.length > 120 ? `${sanitized.slice(0, 117)}...` : sanitized;
};

const createHttpError = (stage: string, response: AxiosResponseLike): Error => {
  const status = response.status;
  const contentType = readHeader(response.headers, 'content-type') ?? 'unknown';
  const preview = createPreview(response.data, contentType);
  const details = preview
    ? `status ${status}, content-type ${contentType}, body ${preview}`
    : `status ${status}, content-type ${contentType}`;
  const hint = stage === 'handshake1' && status === 403
    ? ' Local control may be disabled in the Tapo app (Device Settings > Local Network).'
    : '';
  return new Error(`${stage} failed (${details})${hint}`);
};

const extractSessionCookie = (headers: Record<string, unknown>): string => {
  const raw = readHeader(headers, 'set-cookie');
  if (!raw) {
    throw new Error('handshake1 missing session cookie');
  }
  return raw.split(';')[0];
};

const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest();

const sha1 = (data: string | Buffer) => createHash('sha1').update(data).digest();

const encode = (text: string) => Buffer.from(text, 'utf-8');

const compare = (b1: Buffer, b2: Buffer) => b1.compare(b2) === 0;

const handshake1AuthHash = (localSeed: Buffer, remoteSeed: Buffer, authHash: Buffer) =>
  sha256(Buffer.concat([localSeed, remoteSeed, authHash]));

const handshake2AuthHash = (localSeed: Buffer, remoteSeed: Buffer, authHash: Buffer) =>
  sha256(Buffer.concat([remoteSeed, localSeed, authHash]));

const generateAuthHash = (email: string, password: string) =>
  sha256(Buffer.concat([sha1(email), sha1(password)]));

const deriveKey = (localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) =>
  sha256(Buffer.concat([encode('lsk'), localSeed, remoteSeed, userHash])).slice(0, 16);

const deriveIv = (localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) =>
  sha256(Buffer.concat([encode('iv'), localSeed, remoteSeed, userHash]));

const deriveSig = (localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) =>
  sha256(Buffer.concat([encode('ldk'), localSeed, remoteSeed, userHash])).slice(0, 28);

const deriveSeqFromIv = (iv: Buffer) => iv.slice(iv.length - 4);

const ivWithSeq = (iv: Buffer, seq: Buffer) => Buffer.concat([iv.slice(0, 12), seq]);

const incrementSeq = (seq: Buffer) => {
  const buffer = Buffer.alloc(4);
  buffer.writeInt32BE(seq.readInt32BE() + 1);
  return buffer;
};

const createKlapEncryptionSession = (
  deviceIp: string,
  localSeed: Buffer,
  remoteSeed: Buffer,
  userHash: Buffer,
  sessionCookie: string,
  deviceFactory: TapoDeviceFactory,
  checkError: CheckError,
): TapoDeviceSession => {
  const key = deriveKey(localSeed, remoteSeed, userHash);
  const iv = deriveIv(localSeed, remoteSeed, userHash);
  const sig = deriveSig(localSeed, remoteSeed, userHash);

  let seq = deriveSeqFromIv(iv);

  const encrypt = (payload: unknown) => {
    const payloadJson = JSON.stringify(payload);
    const cipher = createCipheriv(AES_CIPHER_ALGORITHM, key, ivWithSeq(iv, seq));
    const ciphertext = cipher.update(encode(payloadJson));
    return Buffer.concat([ciphertext, cipher.final()]);
  };

  const decrypt = (payload: Buffer): unknown => {
    const cipher = createDecipheriv(AES_CIPHER_ALGORITHM, key, ivWithSeq(iv, seq));
    const ciphertext = cipher.update(payload.slice(32));
    return JSON.parse(Buffer.concat([ciphertext, cipher.final()]).toString());
  };

  const encryptAndSign = (payload: unknown) => {
    const ciphertext = encrypt(payload);
    const signature = sha256(Buffer.concat([sig, seq, ciphertext]));
    return Buffer.concat([signature, ciphertext]);
  };

  const send = async (deviceRequest: unknown): Promise<unknown> => {
    seq = incrementSeq(seq);
    const encryptedRequest = encryptAndSign(deviceRequest);

    const axios = await loadAxios();
    const response = await axios({
      method: 'post',
      url: `http://${deviceIp}/app/request`,
      data: encryptedRequest,
      responseType: 'arraybuffer',
      headers: {
        ...HANDSHAKE_HEADERS,
        Cookie: sessionCookie,
      },
      params: {
        seq: seq.readInt32BE(),
      },
      validateStatus: () => true,
    });

    if (response.status !== 200) {
      throw createHttpError('request', response);
    }

    const decryptedResponse = decrypt(toBuffer(response.data));
    checkError(decryptedResponse);

    return (decryptedResponse as { result?: unknown }).result;
  };

  return deviceFactory({ send });
};

export const loginDeviceByIpKlap: LoginDeviceByIp = async (email, password, deviceIp) => {
  const axios = await loadAxios();
  const [deviceFactory, checkError] = await Promise.all([loadTapoDeviceFactory(), loadCheckError()]);

  const localSeed = randomBytes(16);
  const handshake1Response = await axios.post(`http://${deviceIp}/app/handshake1`, localSeed, {
    responseType: 'arraybuffer',
    headers: HANDSHAKE_HEADERS,
    validateStatus: () => true,
  });

  if (handshake1Response.status === 404) {
    throw new Error('Klap protocol not supported');
  }

  if (handshake1Response.status !== 200) {
    throw createHttpError('handshake1', handshake1Response);
  }

  const responseBytes = toBuffer(handshake1Response.data);
  const sessionCookie = extractSessionCookie(handshake1Response.headers);

  const remoteSeed = responseBytes.slice(0, 16);
  const serverHash = responseBytes.slice(16);
  const localAuthHash = generateAuthHash(email, password);
  const localSeedAuthHash = handshake1AuthHash(localSeed, remoteSeed, localAuthHash);

  if (!compare(localSeedAuthHash, serverHash)) {
    throw new Error('email or password incorrect');
  }

  const payload = handshake2AuthHash(localSeed, remoteSeed, localAuthHash);
  const handshake2Response = await axios.post(`http://${deviceIp}/app/handshake2`, payload, {
    responseType: 'arraybuffer',
    headers: {
      ...HANDSHAKE_HEADERS,
      Cookie: sessionCookie,
    },
    validateStatus: () => true,
  });

  if (handshake2Response.status !== 200) {
    throw createHttpError('handshake2', handshake2Response);
  }

  return createKlapEncryptionSession(
    deviceIp,
    localSeed,
    remoteSeed,
    localAuthHash,
    sessionCookie,
    deviceFactory,
    checkError,
  );
};
