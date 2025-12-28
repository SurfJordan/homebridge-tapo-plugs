import type { Logging } from 'homebridge';
import type { TapoDeviceInfo as ConnectDeviceInfo } from 'tp-link-tapo-connect';

export interface TapoClientOptions {
  host: string;
  username: string;
  password: string;
  timeout?: number;
  log?: Logging;
  loginByIp?: LoginDeviceByIp;
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

export interface TapoDeviceSession {
  turnOn(deviceId?: string): Promise<void>;
  turnOff(deviceId?: string): Promise<void>;
  getDeviceInfo(): Promise<ConnectDeviceInfo>;
  getEnergyUsage(): Promise<Record<string, unknown>>;
}

export type LoginDeviceByIp = (email: string, password: string, deviceIp: string) => Promise<TapoDeviceSession>;

export class TapoClient implements TapoClientLike {
  private readonly host: string;
  private readonly username: string;
  private readonly password: string;
  private readonly timeout?: number;
  private readonly log?: Logging;
  private readonly loginByIp?: LoginDeviceByIp;

  private session?: TapoDeviceSession;
  private loginPromise?: Promise<void>;

  constructor(options: TapoClientOptions) {
    this.host = options.host;
    this.username = options.username;
    this.password = options.password;
    this.timeout = options.timeout;
    this.log = options.log;
    this.loginByIp = options.loginByIp;
  }

  async login(): Promise<void> {
    if (this.session) {
      return;
    }

    if (this.loginPromise) {
      return this.loginPromise;
    }

    this.loginPromise = (async () => {
      if (this.timeout) {
        await this.applyAxiosTimeout(this.timeout);
      }

      const login = this.loginByIp ?? (await this.loadLoginByIp());
      this.session = await login(this.username, this.password, this.host);
    })();

    try {
      await this.loginPromise;
    } finally {
      this.loginPromise = undefined;
    }
  }

  async getDeviceInfo(): Promise<TapoDeviceInfo> {
    const session = await this.getSession();
    const info = await session.getDeviceInfo();

    return {
      deviceId: info.device_id ?? 'unknown-device',
      model: info.model ?? 'Tapo Plug',
      nickname: info.nickname,
      on: Boolean(info.device_on),
      mac: info.mac,
      raw: info,
    };
  }

  async getEnergyUsage(): Promise<TapoEnergyUsage> {
    const session = await this.getSession();
    const usage = await session.getEnergyUsage();

    const currentPower = this.readNumber(usage, 'current_power', 0) ?? 0;
    const todayEnergy = this.readNumber(usage, 'today_energy');
    const monthEnergy = this.readNumber(usage, 'month_energy');
    const totalEnergy = this.readNumber(usage, 'total_energy');
    const voltage = this.readNumber(usage, 'voltage');
    const current = this.readNumber(usage, 'current');

    return {
      currentPower,
      todayEnergy,
      monthEnergy,
      totalEnergy,
      voltage,
      current,
      raw: usage,
    };
  }

  async setPower(on: boolean): Promise<void> {
    const session = await this.getSession();
    if (on) {
      await session.turnOn();
    } else {
      await session.turnOff();
    }
  }

  private async getSession(): Promise<TapoDeviceSession> {
    await this.login();
    if (!this.session) {
      throw new Error('Tapo session not available after login.');
    }
    return this.session;
  }

  private async loadLoginByIp(): Promise<LoginDeviceByIp> {
    const module = await import('tp-link-tapo-connect');
    if (typeof module.loginDeviceByIp !== 'function') {
      throw new Error('tp-link-tapo-connect did not provide loginDeviceByIp');
    }
    return module.loginDeviceByIp as LoginDeviceByIp;
  }

  private async applyAxiosTimeout(timeoutMs: number): Promise<void> {
    try {
      const axiosModule = await import('axios');
      const axiosLike = axiosModule as unknown as {
        default?: { defaults?: { timeout?: number } };
        defaults?: { timeout?: number };
      };
      const defaults = axiosLike.default?.defaults ?? axiosLike.defaults;
      if (defaults) {
        defaults.timeout = timeoutMs;
      }
    } catch (error) {
      this.log?.debug?.('Unable to apply axios timeout override', error);
    }
  }

  private readNumber(source: Record<string, unknown>, key: string, fallback?: number): number | undefined {
    const value = source[key];
    if (typeof value === 'number') {
      return value;
    }
    if (typeof value === 'string' && value.trim() !== '' && !Number.isNaN(Number(value))) {
      return Number(value);
    }
    return fallback;
  }
}
