# Homebridge Tapo Plugs

Local Homebridge platform plugin for TP-Link Tapo smart plugs. It handles on/off control for the whole plug range (P100/P105/P110/P115/EP25 and similar) and exposes energy data for models that report it (for example P110/P115/EP25) using Eve energy characteristics.

## Requirements

- Homebridge v1.8+ (also tested against v2 beta)
- Node.js 18 or newer
- Tapo account email and password (used only to negotiate a local session)
- Static/reserved IPs for plugs are strongly recommended

## Installation

```bash
npm install -g homebridge-tapo-plugs
```

During development you can link the plugin locally:

```bash
npm run build && npm link
```

## Configuration

Add a `TapoPlugs` platform block to your Homebridge `config.json`. Each plug needs its IP or hostname; names are optional because the plugin will read the nickname/model from the device when available.

```json
{
  "platform": "TapoPlugs",
  "name": "Tapo Plugs",
  "username": "you@example.com",
  "password": "your-tapo-password",
  "pollingInterval": 15,
  "devices": [
    {
      "name": "Desk Plug",
      "host": "192.168.1.25"
    },
    {
      "host": "192.168.1.30",
      "pollingInterval": 5
    }
  ]
}
```

- `username` / `password`: Tapo account credentials; you can override per device.
- `pollingInterval`: seconds between status/energy refreshes (set to `0` to disable polling).
- `requestTimeout`: network timeout in seconds (global or per device).
- `devices`: required list of plugs. Each entry supports `name`, `host`, `username`, `password`, `pollingInterval`, and `requestTimeout`.

When energy data is available, the plugin surfaces Eve consumption, voltage, current, and total consumption characteristics alongside the standard HomeKit outlet state. On/off and in-use are available for all plugs.

## Behaviour

- Local-only calls to each plug (`handshake` → `login_device` → `set_device_info` / `get_device_info` / `get_energy_usage`).
- Accessories are created/updated at launch; removed when a device is deleted from the config.
- Model and nickname are pulled from the device automatically so you don’t need to enter the model manually.

## Development & Testing

- `npm test` runs the Jest suite for the Tapo client and platform wiring.
- `npm run build` compiles TypeScript to `dist/`.
- A sample Homebridge config lives in `test/hbConfig` for use with `npm run watch`.

## Notes

- Credentials are only kept in memory and sent to the device during login; they are not persisted to disk by the plugin.
- Energy readings rely on the device supporting `get_energy_usage`; non-energy models simply expose on/off.
- Ensure your Homebridge host can reach the plug IPs directly on the local network.
