jest.mock('homebridge-lib/EveHomeKitTypes', () => ({
  EveHomeKitTypes: class {
    Characteristics = {};
    Services = {};
    constructor() {
      return this;
    }
  },
}));

import { TapoPlatform } from '../src/platform.js';
import { PLATFORM_NAME, PLUGIN_NAME } from '../src/settings.js';

class FakeCharacteristic {
  public value: unknown;
  private getHandler?: () => unknown | Promise<unknown>;
  private setHandler?: (value: unknown) => unknown | Promise<unknown>;

  constructor(public readonly name: string) {}

  onGet(handler: () => unknown | Promise<unknown>) {
    this.getHandler = handler;
    return this;
  }

  onSet(handler: (value: unknown) => unknown | Promise<unknown>) {
    this.setHandler = handler;
    return this;
  }

  async handleGet() {
    return this.getHandler?.();
  }

  async handleSet(value: unknown) {
    this.value = value;
    return this.setHandler?.(value);
  }
}

class FakeService {
  public characteristics = new Map<string, FakeCharacteristic>();

  constructor(public readonly name: string) {}

  getCharacteristic(key: string) {
    if (!this.characteristics.has(key)) {
      this.characteristics.set(key, new FakeCharacteristic(key));
    }
    return this.characteristics.get(key)!;
  }

  setCharacteristic(key: string, value: unknown) {
    const characteristic = this.getCharacteristic(key);
    characteristic.value = value;
    return this;
  }

  updateCharacteristic(key: string, value: unknown) {
    return this.setCharacteristic(key, value);
  }
}

class FakeAccessory {
  public readonly services = new Map<string, FakeService>();
  public readonly context: Record<string, unknown> = {};

  constructor(public displayName: string, public UUID: string) {}

  getService(name: string) {
    return this.services.get(name);
  }

  addService(name: string) {
    const service = new FakeService(name);
    this.services.set(name, service);
    return service;
  }
}

class FakeApi {
  public readonly hap = {
    Service: {
      AccessoryInformation: 'AccessoryInformation',
      Outlet: 'Outlet',
    },
    Characteristic: {
      Manufacturer: 'Manufacturer',
      Model: 'Model',
      SerialNumber: 'SerialNumber',
      Name: 'Name',
      On: 'On',
      OutletInUse: 'OutletInUse',
    },
    HAPStatus: {
      SERVICE_COMMUNICATION_FAILURE: -70402,
    },
    HapStatusError: class extends Error {
      constructor(public readonly hapStatus: number) {
        super('hap-status');
      }
    },
    uuid: {
      generate: (value: string) => `uuid-${value}`,
    },
  };

  public readonly platformAccessory = FakeAccessory;
  private readonly listeners = new Map<string, () => void>();
  public registeredAccessories: FakeAccessory[] = [];
  public unregisteredAccessories: FakeAccessory[] = [];

  on(event: string, handler: () => void) {
    this.listeners.set(event, handler);
  }

  trigger(event: string) {
    this.listeners.get(event)?.();
  }

  registerPlatformAccessories(_pluginName: string, _platform: string, accessories: FakeAccessory[]) {
    this.registeredAccessories.push(...accessories);
  }

  unregisterPlatformAccessories(_pluginName: string, _platform: string, accessories: FakeAccessory[]) {
    this.unregisteredAccessories.push(...accessories);
  }
}

class FakeClient {
  public isOn = true;
  login = jest.fn().mockResolvedValue(undefined);
  getDeviceInfo = jest.fn().mockResolvedValue({
    deviceId: 'device-1',
    model: 'P110',
    nickname: 'Desk Plug',
    on: this.isOn,
  });
  getEnergyUsage = jest.fn().mockResolvedValue({
    currentPower: 4.2,
    todayEnergy: 1.4,
    monthEnergy: 10.1,
  });
  setPower = jest.fn(async (value: boolean) => {
    this.isOn = value;
  });
}

const log = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

describe('TapoPlatform', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('registers configured devices and wires on/off control', async () => {
    const api = new FakeApi();
    const client = new FakeClient();
    const platform = new TapoPlatform(
      log as never,
      {
        platform: PLATFORM_NAME,
        name: 'Tapo',
        username: 'user',
        password: 'pass',
        pollingInterval: 0,
        devices: [{ name: 'Desk', host: '10.0.0.2' }],
      } as never,
      api as never,
      () => client,
    );

    api.trigger('didFinishLaunching');
    await Promise.resolve();
    await Promise.resolve();

    expect(api.registeredAccessories).toHaveLength(1);
    const accessory = api.registeredAccessories[0];
    const outletService = accessory.getService(api.hap.Service.Outlet);
    expect(outletService).toBeDefined();

    const onCharacteristic = outletService!.getCharacteristic(api.hap.Characteristic.On);
    await onCharacteristic.handleSet(false);
    expect(client.setPower).toHaveBeenCalledWith(false);
  });
});
