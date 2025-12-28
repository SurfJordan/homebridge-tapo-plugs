import { TapoClient } from '../src/tapo/client.js';

describe('TapoClient', () => {
  const host = '192.168.1.50';
  const credentials = { username: 'user@example.com', password: 'secret-password' };

  it('logs in via loginDeviceByIp and maps device info', async () => {
    const session = {
      turnOn: jest.fn(),
      turnOff: jest.fn(),
      getDeviceInfo: jest.fn().mockResolvedValue({
        device_id: 'ABC123',
        model: 'P110',
        nickname: 'Desk Plug',
        device_on: true,
        mac: 'aa:bb:cc:dd:ee:ff',
      }),
      getEnergyUsage: jest.fn(),
    };

    const loginByIp = jest.fn().mockResolvedValue(session);
    const client = new TapoClient({ host, ...credentials, loginByIp });

    const info = await client.getDeviceInfo();

    expect(loginByIp).toHaveBeenCalledWith(credentials.username, credentials.password, host);
    expect(info.deviceId).toBe('ABC123');
    expect(info.model).toBe('P110');
    expect(info.nickname).toBe('Desk Plug');
    expect(info.on).toBe(true);
    expect(info.mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('maps energy usage numbers', async () => {
    const session = {
      turnOn: jest.fn(),
      turnOff: jest.fn(),
      getDeviceInfo: jest.fn(),
      getEnergyUsage: jest.fn().mockResolvedValue({
        current_power: '6.4',
        today_energy: 12.2,
        month_energy: 30.5,
        total_energy: 100.1,
        voltage: '231',
        current: 0.18,
      }),
    };

    const loginByIp = jest.fn().mockResolvedValue(session);
    const client = new TapoClient({ host, ...credentials, loginByIp });

    const usage = await client.getEnergyUsage();

    expect(usage.currentPower).toBe(6.4);
    expect(usage.todayEnergy).toBe(12.2);
    expect(usage.monthEnergy).toBe(30.5);
    expect(usage.totalEnergy).toBe(100.1);
    expect(usage.voltage).toBe(231);
    expect(usage.current).toBe(0.18);
  });

  it('turns the device on and off', async () => {
    const session = {
      turnOn: jest.fn().mockResolvedValue(undefined),
      turnOff: jest.fn().mockResolvedValue(undefined),
      getDeviceInfo: jest.fn(),
      getEnergyUsage: jest.fn(),
    };

    const loginByIp = jest.fn().mockResolvedValue(session);
    const client = new TapoClient({ host, ...credentials, loginByIp });

    await client.setPower(true);
    await client.setPower(false);

    expect(session.turnOn).toHaveBeenCalledTimes(1);
    expect(session.turnOff).toHaveBeenCalledTimes(1);
  });
});
