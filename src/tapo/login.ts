import type { Logging } from 'homebridge';

import type { LoginDeviceByIp } from './client.js';

type LoginModule = {
  loginDeviceByIp?: LoginDeviceByIp;
  default?: {
    loginDeviceByIp?: LoginDeviceByIp;
  };
};

export const isKlapUnsupported = (error: unknown): boolean => {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    return message.includes('klap protocol not supported') || message.includes('status code 404');
  }

  return false;
};

export const createLoginByIp = (
  loginKlap: LoginDeviceByIp,
  loginLegacy: LoginDeviceByIp,
  log?: Logging,
): LoginDeviceByIp => {
  return async (email, password, deviceIp) => {
    try {
      return await loginKlap(email, password, deviceIp);
    } catch (error) {
      if (isKlapUnsupported(error)) {
        log?.debug?.('KLAP not supported on %s, falling back to legacy login', deviceIp);
        return loginLegacy(email, password, deviceIp);
      }
      throw error;
    }
  };
};

export const getLoginByIp = (module: unknown, moduleLabel: string): LoginDeviceByIp => {
  const login =
    (module as LoginModule).loginDeviceByIp ??
    (module as LoginModule).default?.loginDeviceByIp;

  if (typeof login !== 'function') {
    throw new Error(`tp-link-tapo-connect did not provide loginDeviceByIp in ${moduleLabel}`);
  }

  return login;
};
