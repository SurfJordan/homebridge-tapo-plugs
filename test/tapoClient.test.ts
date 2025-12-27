import crypto from 'crypto';

import { TapoClient } from '../src/tapo/client.js';

const deviceKey = Buffer.from('0123456789abcdef');
const aesKey = deviceKey.slice(0, 16);
const iv = aesKey;

function wrapPublicKey(key: string): string {
  const lines = key.match(/.{1,64}/g) ?? [key];
  return `-----BEGIN RSA PUBLIC KEY-----\n${lines.join('\n')}\n-----END RSA PUBLIC KEY-----\n`;
}

function encryptPayload(payload: unknown): string {
  const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return encrypted.toString('base64');
}

function decryptPayload<T>(input: string): T {
  const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
  const decrypted = Buffer.concat([decipher.update(Buffer.from(input, 'base64')), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8')) as T;
}

describe('TapoClient', () => {
  const host = '192.168.1.50';
  const credentials = { username: 'user@example.com', password: 'secret-password' };

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  it('handshakes, logs in, and fetches device info', async () => {
    let call = 0;

    const fetchMock: jest.MockedFunction<typeof fetch> = jest.fn(async (url, options) => {
      call += 1;
      const body = JSON.parse((options?.body as string) ?? '{}');

      if (call === 1) {
        expect(body.method).toBe('handshake');
        const publicKey = wrapPublicKey(body.params.key);
        const encryptedKey = crypto.publicEncrypt(
          { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
          deviceKey,
        );

        return new Response(JSON.stringify({
          error_code: 0,
          result: { key: encryptedKey.toString('base64') },
        }), {
          status: 200,
          headers: { 'set-cookie': 'TP_SESSIONID=session123' },
        });
      }

      if (call === 2) {
        expect(url).toBe(`http://${host}/app`);
        const decrypted = decryptPayload<{ method: string; params: { username: string; password: string } }>(body.params.request);
        expect(decrypted.method).toBe('login_device');
        expect(decrypted.params.username).toBe(Buffer.from(credentials.username).toString('base64'));

        const encryptedResponse = encryptPayload({
          error_code: 0,
          result: { token: 'token123', device_id: 'ABC123', model: 'P110' },
        });

        return new Response(JSON.stringify({
          error_code: 0,
          result: { response: encryptedResponse },
        }), {
          status: 200,
          headers: { 'set-cookie': 'TP_SESSIONID=session123' },
        });
      }

      if (call === 3) {
        expect(url).toBe(`http://${host}/app?token=token123`);
        const decrypted = decryptPayload<{ method: string }>(body.params.request);
        expect(decrypted.method).toBe('get_device_info');
        expect((options?.headers as Record<string, string>).Cookie).toContain('TP_SESSIONID=session123');

        const encryptedResponse = encryptPayload({
          error_code: 0,
          result: {
            device_on: true,
            nickname: 'Desk Plug',
            model: 'P110',
            device_id: 'ABC123',
          },
        });

        return new Response(JSON.stringify({
          error_code: 0,
          result: { response: encryptedResponse },
        }), { status: 200 });
      }

      throw new Error('unexpected call');
    });

    const client = new TapoClient({ host, ...credentials, fetch: fetchMock });
    const info = await client.getDeviceInfo();

    expect(info.model).toBe('P110');
    expect(info.on).toBe(true);
    expect(info.deviceId).toBe('ABC123');
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('retrieves energy usage with an existing session', async () => {
    let call = 0;

    const fetchMock: jest.MockedFunction<typeof fetch> = jest.fn(async (url, options) => {
      call += 1;
      const body = JSON.parse((options?.body as string) ?? '{}');

      if (call === 1) {
        const publicKey = wrapPublicKey(body.params.key);
        const encryptedKey = crypto.publicEncrypt(
          { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
          deviceKey,
        );

        return new Response(JSON.stringify({
          error_code: 0,
          result: { key: encryptedKey.toString('base64') },
        }), {
          status: 200,
          headers: { 'set-cookie': 'TP_SESSIONID=session123' },
        });
      }

      if (call === 2) {
        const encryptedResponse = encryptPayload({
          error_code: 0,
          result: { token: 'token123' },
        });

        return new Response(JSON.stringify({
          error_code: 0,
          result: { response: encryptedResponse },
        }), {
          status: 200,
          headers: { 'set-cookie': 'TP_SESSIONID=session123' },
        });
      }

      if (call === 3) {
        expect(url).toBe(`http://${host}/app?token=token123`);
        const decrypted = decryptPayload<{ method: string }>(body.params.request);
        expect(decrypted.method).toBe('get_energy_usage');

        const encryptedResponse = encryptPayload({
          error_code: 0,
          result: {
            current_power: 6.4,
            today_energy: 12.2,
            month_energy: 30.5,
          },
        });

        return new Response(JSON.stringify({
          error_code: 0,
          result: { response: encryptedResponse },
        }), { status: 200 });
      }

      throw new Error('unexpected call');
    });

    const client = new TapoClient({ host, ...credentials, fetch: fetchMock });
    await client.login();
    const energy = await client.getEnergyUsage();

    expect(energy.currentPower).toBe(6.4);
    expect(energy.todayEnergy).toBe(12.2);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
