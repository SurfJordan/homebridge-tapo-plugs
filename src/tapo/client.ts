import {
  constants,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  privateDecrypt,
} from 'node:crypto';
import type { Logging } from 'homebridge';

export interface TapoClientOptions {
  host: string;
  username: string;
  password: string;
  timeout?: number;
  fetch?: typeof fetch;
  log?: Logging;
}

export interface TapoDeviceInfo {
  deviceId: string;
  model: string;
  nickname?: string;
  on: boolean;
  mac?: string;
  raw?: unknown;
}

export interface TapoEnergyUsage {
  currentPower: number;
  todayEnergy?: number;
  monthEnergy?: number;
  totalEnergy?: number;
  voltage?: number;
  current?: number;
  raw?: unknown;
}

export interface TapoClientLike {
  login(): Promise<void>;
  getDeviceInfo(): Promise<TapoDeviceInfo>;
  getEnergyUsage(): Promise<TapoEnergyUsage>;
  setPower(on: boolean): Promise<void>;
}

interface TapoResponse<T = unknown> {
  error_code?: number;
  result?: T;
  msg?: string;
}

const DEFAULT_TIMEOUT = 8000;

export class TapoClient implements TapoClientLike {
  private readonly baseUrl: string;
  private readonly username: string;
  private readonly password: string;
  private readonly timeout: number;
  private readonly fetchImpl: typeof fetch;
  private readonly log?: Logging;

  private token?: string;
  private cookie?: string;
  private aesKey?: Buffer;
  private iv?: Buffer;
  private loginPromise?: Promise<void>;
  private readonly keyPairs = [
    generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 0x10001 }),
    generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 }),
  ];

  constructor(options: TapoClientOptions) {
    this.username = options.username;
    this.password = options.password;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
    this.fetchImpl = options.fetch ?? fetch;
    this.log = options.log;

    const host = options.host.startsWith('http') ? options.host : `http://${options.host}`;
    this.baseUrl = `${host.replace(/\/+$/, '')}/app`;
  }

  async login(): Promise<void> {
    if (this.token) {
      return;
    }

    if (this.loginPromise) {
      return this.loginPromise;
    }

    this.loginPromise = (async () => {
      await this.handshake();
      const encodedUser = Buffer.from(this.username).toString('base64');
      const encodedPass = Buffer.from(this.password).toString('base64');

      const response = await this.secureRequest<{ token?: string }>({
        method: 'login_device',
        params: {
          username: encodedUser,
          password: encodedPass,
        },
      }, false);

      const token = response.result?.token ?? (response as unknown as { token?: string }).token;
      if (!token) {
        throw new Error('Tapo login failed: token missing from response');
      }
      this.token = token;
    })();

    try {
      await this.loginPromise;
    } finally {
      this.loginPromise = undefined;
    }
  }

  async getDeviceInfo(): Promise<TapoDeviceInfo> {
    const response = await this.secureRequest<{
      device_id?: string;
      model?: string;
      nickname?: string;
      alias?: string;
      device_on?: boolean;
      mac?: string;
    }>({
      method: 'get_device_info',
    });

    const result = response.result ?? {};
    return {
      deviceId: result.device_id ?? 'unknown-device',
      model: result.model ?? 'Tapo Plug',
      nickname: result.nickname ?? result.alias,
      on: Boolean(result.device_on),
      mac: result.mac,
      raw: response,
    };
  }

  async getEnergyUsage(): Promise<TapoEnergyUsage> {
    const response = await this.secureRequest<{
      current_power?: number;
      today_energy?: number;
      month_energy?: number;
      local_time?: string;
      voltage?: number;
      current?: number;
      total_energy?: number;
    }>({
      method: 'get_energy_usage',
    });

    const result = response.result ?? {};
    return {
      currentPower: result.current_power ?? 0,
      todayEnergy: result.today_energy ?? undefined,
      monthEnergy: result.month_energy ?? undefined,
      totalEnergy: result.total_energy ?? undefined,
      voltage: result.voltage ?? undefined,
      current: result.current ?? undefined,
      raw: response,
    };
  }

  async setPower(on: boolean): Promise<void> {
    await this.secureRequest({
      method: 'set_device_info',
      params: { device_on: on },
    });
  }

  private async secureRequest<T = unknown>(payload: Record<string, unknown>, includeToken = true): Promise<TapoResponse<T>> {
    if (includeToken) {
      await this.login();
    } else {
      await this.handshake();
    }

    const encryptedPayload = this.encrypt(JSON.stringify(payload));

    const { data } = await this.send(
      {
        method: 'securePassthrough',
        params: { request: encryptedPayload },
        requestTimeMils: Date.now(),
      },
      includeToken,
    );

    this.ensureOk(data, 'securePassthrough');

    const encryptedResponse = (data.result as { response?: string } | undefined)?.response;
    if (typeof encryptedResponse !== 'string') {
      throw new Error('Malformed Tapo response: missing encrypted payload');
    }

    const decrypted = JSON.parse(this.decrypt(encryptedResponse)) as TapoResponse<T>;
    const method = typeof payload.method === 'string' ? payload.method : 'request';
    this.ensureOk(decrypted, method);

    return decrypted;
  }

  private async handshake(): Promise<void> {
    if (this.aesKey && this.iv) {
      return;
    }

    const plans = this.getHandshakePlans();
    let lastError: TapoResponse | undefined;

    for (const keyPair of this.keyPairs) {
      const candidates = this.getHandshakeKeyCandidates(keyPair);
      for (const candidate of candidates) {
        for (const plan of plans) {
          const { data, headers } = await this.send(plan.build(candidate.value), false);
          this.updateCookie(headers);

          const errorCode = data.error_code ?? 0;
          if (errorCode !== 0) {
            lastError = data;
            if (errorCode === 1003) {
              this.log?.debug?.('Handshake rejected (%s/%s), trying next.', candidate.label, plan.label);
              continue;
            }
            this.ensureOk(data, 'handshake');
          }

          const encryptedKey = (data.result as { key?: string } | undefined)?.key;
          if (!encryptedKey) {
            throw new Error('Handshake failed: key missing from response');
          }

          const decryptedKey = privateDecrypt(
            { key: keyPair.privateKey, padding: constants.RSA_PKCS1_PADDING },
            Buffer.from(encryptedKey, 'base64'),
          );

          const { key, iv } = this.deriveKeyAndIv(decryptedKey);
          this.aesKey = key;
          this.iv = iv;
          return;
        }
      }
    }

    if (lastError) {
      this.ensureOk(lastError, 'handshake');
    }

    throw new Error('Handshake failed: no response from device');
  }

  private async send(body: Record<string, unknown>, includeToken: boolean): Promise<{ data: TapoResponse; headers: Headers }> {
    const url = includeToken && this.token ? `${this.baseUrl}?token=${this.token}` : this.baseUrl;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.cookie ? { Cookie: this.cookie } : {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      this.updateCookie(response.headers);

      const raw = await response.text();
      const contentType = response.headers.get('content-type') ?? 'unknown';
      const server = response.headers.get('server') ?? 'unknown';
      let data: TapoResponse;
      try {
        data = JSON.parse(raw) as TapoResponse;
      } catch (error) {
        const preview = raw.trim().slice(0, 160).replace(/\s+/g, ' ');
        this.log?.warn?.(
          'Tapo returned non-JSON response (status %s, content-type %s, server %s): %s',
          response.status,
          contentType,
          server,
          preview,
        );
        throw new Error(`Tapo device returned non-JSON response (status ${response.status}). Check IP, network isolation, and device setup mode.`);
      }
      return { data, headers: response.headers };
    } catch (error) {
      this.log?.debug?.('Tapo request failed', error);
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private encrypt(payload: string): string {
    if (!this.aesKey || !this.iv) {
      throw new Error('Encryption attempted without a session key');
    }
    const cipher = createCipheriv('aes-128-cbc', this.aesKey, this.iv);
    const encrypted = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
    return encrypted.toString('base64');
  }

  private decrypt(payload: string): string {
    if (!this.aesKey || !this.iv) {
      throw new Error('Decryption attempted without a session key');
    }
    const decipher = createDecipheriv('aes-128-cbc', this.aesKey, this.iv);
    const decrypted = Buffer.concat([decipher.update(Buffer.from(payload, 'base64')), decipher.final()]);
    return decrypted.toString('utf8');
  }

  private updateCookie(headers: Headers) {
    const headerWithSetCookie = headers as Headers & { getSetCookie?: () => string[] };
    const setCookies = typeof headerWithSetCookie.getSetCookie === 'function' ? headerWithSetCookie.getSetCookie() : [];
    const rawCookie = setCookies[0] ?? headers.get('set-cookie');

    if (!rawCookie) {
      return;
    }

    this.cookie = rawCookie.split(';')[0];
  }

  private ensureOk(response: TapoResponse, context?: string) {
    const errorCode = response.error_code ?? 0;
    if (errorCode !== 0) {
      this.log?.debug?.('Tapo error response', response);
      const prefix = context ? `Tapo request (${context}) failed` : 'Tapo request failed';
      throw new Error(`${prefix} with code ${errorCode}${response.msg ? `: ${response.msg}` : ''}`);
    }
  }

  private deriveKeyAndIv(keyMaterial: Buffer): { key: Buffer; iv: Buffer } {
    const asString = keyMaterial.toString('utf8').trim();
    if (/^[0-9a-fA-F]+$/.test(asString) && (asString.length === 32 || asString.length === 64)) {
      const parsed = Buffer.from(asString, 'hex');
      if (parsed.length >= 32) {
        return { key: parsed.slice(0, 16), iv: parsed.slice(16, 32) };
      }
      return { key: parsed.slice(0, 16), iv: parsed.slice(0, 16) };
    }

    if (keyMaterial.length >= 32) {
      return { key: keyMaterial.slice(0, 16), iv: keyMaterial.slice(16, 32) };
    }

    return { key: keyMaterial.slice(0, 16), iv: keyMaterial.slice(0, 16) };
  }

  private getHandshakeKeyCandidates(keyPair: ReturnType<typeof generateKeyPairSync>) {
    const pkcs1Der = keyPair.publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64');
    const spkiDer = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const pkcs1Pem = keyPair.publicKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    const spkiPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const pkcs1DerWrapped = this.wrapBase64(pkcs1Der);
    const spkiDerWrapped = this.wrapBase64(spkiDer);

    return [
      { label: 'pkcs1-der', value: pkcs1Der },
      { label: 'spki-der', value: spkiDer },
      { label: 'pkcs1-der-lines', value: pkcs1DerWrapped },
      { label: 'spki-der-lines', value: spkiDerWrapped },
      { label: 'pkcs1-pem', value: pkcs1Pem },
      { label: 'spki-pem', value: spkiPem },
    ];
  }

  private getHandshakePlans() {
    const now = Date.now();
    return [
      {
        label: 'root-requestTime',
        build: (key: string) => ({
          method: 'handshake',
          params: { key },
          requestTimeMils: now,
        }),
      },
      {
        label: 'params-requestTime',
        build: (key: string) => ({
          method: 'handshake',
          params: { key, requestTimeMils: now },
        }),
      },
      {
        label: 'minimal',
        build: (key: string) => ({
          method: 'handshake',
          params: { key },
        }),
      },
    ];
  }

  private wrapBase64(value: string): string {
    return value.match(/.{1,64}/g)?.join('\n') ?? value;
  }
}
