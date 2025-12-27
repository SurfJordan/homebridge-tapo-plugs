import type { CharacteristicValue, PlatformAccessory, Service } from 'homebridge';

import type { TapoPlatform, TapoDeviceConfig } from './platform.js';
import type { TapoClientLike, TapoDeviceInfo, TapoEnergyUsage } from './tapo/client.js';

export class TapoPlugAccessory {
  private readonly service: Service;
  private pollTimer?: NodeJS.Timeout;
  private currentOn?: boolean;
  private readonly name: string;

  constructor(
    private readonly platform: TapoPlatform,
    private readonly accessory: PlatformAccessory,
    private readonly client: TapoClientLike,
    private readonly deviceConfig: TapoDeviceConfig,
    initialInfo?: TapoDeviceInfo,
  ) {
    const infoService = this.accessory.getService(this.platform.Service.AccessoryInformation)
      || this.accessory.addService(this.platform.Service.AccessoryInformation);

    infoService
      .setCharacteristic(this.platform.Characteristic.Manufacturer, 'TP-Link Tapo')
      .setCharacteristic(this.platform.Characteristic.Model, initialInfo?.model ?? 'Tapo Plug')
      .setCharacteristic(this.platform.Characteristic.SerialNumber, initialInfo?.deviceId ?? this.deviceConfig.host);

    this.service = this.accessory.getService(this.platform.Service.Outlet)
      || this.accessory.addService(this.platform.Service.Outlet);

    this.name = this.deviceConfig.name ?? initialInfo?.nickname ?? this.accessory.displayName;
    this.service.setCharacteristic(this.platform.Characteristic.Name, this.name);

    this.service.getCharacteristic(this.platform.Characteristic.On)
      .onSet(this.handleSetOn.bind(this))
      .onGet(this.handleGetOn.bind(this));

    this.service.getCharacteristic(this.platform.Characteristic.OutletInUse)
      .onGet(async () => this.currentOn ?? false);

    if (initialInfo) {
      this.updateFromDeviceInfo(initialInfo);
    }

    const pollingSeconds = this.deviceConfig.pollingInterval ?? this.platform.config.pollingInterval ?? 15;
    if (pollingSeconds > 0) {
      const intervalMs = Math.max(1000, pollingSeconds * 1000);
      const jitterMs = Math.floor(Math.random() * Math.min(intervalMs / 2, 5000));

      this.pollTimer = setTimeout(() => {
        void this.refreshFromDevice();
        this.pollTimer = setInterval(() => {
          void this.refreshFromDevice();
        }, intervalMs);
      }, jitterMs);
    }
  }

  private async handleSetOn(value: CharacteristicValue) {
    const target = value as boolean;
    try {
      await this.client.setPower(target);
      this.currentOn = target;
      this.service.updateCharacteristic(this.platform.Characteristic.On, target);
      this.service.updateCharacteristic(this.platform.Characteristic.OutletInUse, target);
      this.platform.log.debug('Set %s to %s', this.name, target);
    } catch (error) {
      this.platform.log.warn('Failed to set %s: %s', this.name, (error as Error).message);
      throw this.toHapError(error);
    }
  }

  private async handleGetOn(): Promise<CharacteristicValue> {
    if (this.currentOn !== undefined) {
      return this.currentOn;
    }

    try {
      const info = await this.client.getDeviceInfo();
      this.updateFromDeviceInfo(info);
      return this.currentOn ?? false;
    } catch (error) {
      this.platform.log.warn('Failed to fetch state for %s: %s', this.name, (error as Error).message);
      throw this.toHapError(error);
    }
  }

  private async refreshFromDevice() {
    try {
      const info = await this.client.getDeviceInfo();
      this.updateFromDeviceInfo(info);
    } catch (error) {
      this.platform.log.warn('Failed to refresh %s: %s', this.name, (error as Error).message);
      return;
    }

    try {
      const energy = await this.client.getEnergyUsage();
      this.updateEnergy(energy);
    } catch (error) {
      this.platform.log.debug('Energy data unavailable for %s: %s', this.name, (error as Error).message);
    }
  }

  private updateFromDeviceInfo(info: TapoDeviceInfo) {
    this.currentOn = info.on;
    this.service.updateCharacteristic(this.platform.Characteristic.On, info.on);
    this.service.updateCharacteristic(this.platform.Characteristic.OutletInUse, info.on);
  }

  private updateEnergy(energy: TapoEnergyUsage) {
    const characteristics = this.platform.CustomCharacteristics;

    if (characteristics?.Consumption) {
      this.service.updateCharacteristic(characteristics.Consumption, energy.currentPower ?? 0);
    }

    if (characteristics?.Voltage && energy.voltage !== undefined) {
      this.service.updateCharacteristic(characteristics.Voltage, energy.voltage);
    }

    if (characteristics?.ElectricCurrent && energy.current !== undefined) {
      this.service.updateCharacteristic(characteristics.ElectricCurrent, energy.current);
    }

    const total = energy.totalEnergy ?? energy.monthEnergy ?? energy.todayEnergy;
    if (characteristics?.TotalConsumption && total !== undefined) {
      const normalizedTotal = total > 1000 ? total / 1000 : total;
      this.service.updateCharacteristic(characteristics.TotalConsumption, normalizedTotal);
    }
  }

  private toHapError(error: unknown) {
    this.platform.log.debug('Detail for %s failure: %o', this.name, error);
    return new this.platform.api.hap.HapStatusError(this.platform.api.hap.HAPStatus.SERVICE_COMMUNICATION_FAILURE);
  }
}
