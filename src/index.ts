import type { API } from 'homebridge';

import { TapoPlatform } from './platform.js';
import { PLATFORM_NAME } from './settings.js';

/**
 * This method registers the platform with Homebridge
 */
export default (api: API) => {
  console.log('🔥🔥🔥 TAPO PLUGIN ENTRY LOADED', __filename);
  api.registerPlatform(PLATFORM_NAME, TapoPlatform);
};
