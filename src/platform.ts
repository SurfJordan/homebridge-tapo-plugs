import type {
  API,
  Characteristic,
  DynamicPlatformPlugin,
  Logging,
  PlatformAccessory,
  PlatformConfig,
  Service,
} from 'homebridge';
import { EveHomeKitTypes } from 'homebridge-lib/EveHomeKitTypes';

import { TapoPlugAccessory } from './platformAccessory.js';
import { PLATFORM_NAME, PLUGIN_NAME } from './settings.js';
import { TapoClient, type TapoClientLike, type TapoDeviceInfo } from './tapo/client.js';

export interface TapoDeviceConfig {
  name?: string;
  host: string;
  username?: string;
  password?: string;
  pollingInterval?: number;
  requestTimeout?: number;
}

export interface TapoPlatformConfig extends PlatformConfig {
  username?: string;
  password?: string;
  pollingInterval?: number;
  requestTimeout?: number;
  devices?: TapoDeviceConfig[];
}

export type ClientFactory = (device: TapoDeviceConfig, platform: TapoPlatformConfig) => TapoClientLike;

export class TapoPlatform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service;
  public readonly Characteristic: typeof Characteristic;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public readonly CustomCharacteristics: Record<string, any>;

  public readonly accessories: Map<string, PlatformAccessory> = new Map();

  private readonly clientFactory: ClientFactory;

  constructor(
    public readonly log: Logging,
    public readonly config: TapoPlatformConfig,
    public readonly api: API,
    clientFactory?: ClientFactory,
  ) {
    this.Service = api.hap.Service;
    this.Characteristic = api.hap.Characteristic;

    const eveTypes = new EveHomeKitTypes(api);
    this.CustomCharacteristics = eveTypes.Characteristics;

    this.clientFactory = clientFactory ?? ((device) => new TapoClient({
      host: device.host,
      username: device.username ?? this.config.username ?? '',
      password: device.password ?? this.config.password ?? '',
      timeout: (device.requestTimeout ?? this.config.requestTimeout ?? 8) * 1000,
      log: this.log,
    }));

    this.log.error("🔥 TAPO platform constructor reached");
    this.log.debug("🔥 TAPO debug test");

    if (!config || !config.name) {
      this.log.warn('No configuration found for Tapo platform.');
      return;
    }

    this.api.on('didFinishLaunching', () => {
      this.log.debug('Tapo platform didFinishLaunching, starting discovery.');
      void this.discoverDevices();
    });
  }

  configureAccessory(accessory: PlatformAccessory) {
    this.log.info('Loading accessory from cache:', accessory.displayName);
    this.accessories.set(accessory.UUID, accessory);
  }

  private getPollingIntervalSeconds(device?: TapoDeviceConfig): number {
    return device?.pollingInterval ?? this.config.pollingInterval ?? 15;
  }

  private getTimeoutSeconds(device?: TapoDeviceConfig): number {
    return device?.requestTimeout ?? this.config.requestTimeout ?? 8;
  }

  private getDevices(): TapoDeviceConfig[] {
    if (!Array.isArray(this.config.devices)) {
      return [];
    }
    return this.config.devices.filter((device) => typeof device.host === 'string' && device.host.length > 0);
  }

  private async discoverDevices(): Promise<void> {
    const devices = this.getDevices();
    const seen = new Set<string>();

    if (!devices.length) {
      this.log.warn('No Tapo devices configured.');
    }

    const tasks = devices.map(async (device) => {
      const username = device.username ?? this.config.username;
      const password = device.password ?? this.config.password;

      if (!username || !password) {
        this.log.warn('Skipping %s because username/password are missing', device.host);
        return;
      }

      const uuid = this.api.hap.uuid.generate(device.host);
      seen.add(uuid);

      const client = this.clientFactory({
        ...device,
        username,
        password,
        pollingInterval: this.getPollingIntervalSeconds(device),
        requestTimeout: this.getTimeoutSeconds(device),
      }, this.config);

      let deviceInfo: TapoDeviceInfo;
      try {
        deviceInfo = await client.getDeviceInfo();
      } catch (error) {
        this.log.warn('Could not reach %s: %s', device.host, (error as Error).message);
        return;
      }

      const displayName = device.name ?? deviceInfo.nickname ?? deviceInfo.model ?? device.host;

      let accessory = this.accessories.get(uuid);
      if (accessory) {
        accessory.context.device = {
          ...device,
          displayName,
          deviceId: deviceInfo.deviceId,
        };
        this.log.info('Updating cached accessory %s', accessory.displayName);
      } else {
        accessory = new this.api.platformAccessory(displayName, uuid);
        accessory.context.device = {
          ...device,
          displayName,
          deviceId: deviceInfo.deviceId,
        };
        this.log.info('Adding new accessory %s', accessory.displayName);
      }

      new TapoPlugAccessory(this, accessory, client, device, deviceInfo);

      if (this.accessories.has(uuid)) {
        this.api.updatePlatformAccessories([accessory]);
      } else {
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
        this.accessories.set(uuid, accessory);
      }
    });

    await Promise.all(tasks);

    for (const [uuid, accessory] of Array.from(this.accessories.entries())) {
      if (!seen.has(uuid)) {
        this.log.info('Removing stale accessory %s', accessory.displayName);
        this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
        this.accessories.delete(uuid);
      }
    }
  }
}
