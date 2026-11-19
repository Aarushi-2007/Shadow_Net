// SadraNet / ShadowNet BLE client (Capacitor version).
//
// Works in two places with the same code:
//   - Android app (Capacitor): uses native Android Bluetooth
//   - Chrome / Edge on the web: the plugin falls back to Web Bluetooth
//
// The exported functions match the old Web Bluetooth version,
// so App.jsx does not need to change.
//
// UUIDs and advertised names must match the ESP32 firmware.

import { Capacitor } from "@capacitor/core";
import { BleClient } from "@capacitor-community/bluetooth-le";

export const BLE_CONFIG = {
  service: "12345678-1234-1234-1234-123456789000",
  message: "12345678-1234-1234-1234-123456789001",
  status: "12345678-1234-1234-1234-123456789002",
};

// NOTE: App.jsx displays "SadraNet_F1" etc., but these are the names
// actually used to find devices. Keep them identical to the firmware.
const NODE_CONFIG = {
  F1: {
    name: "ShadowNet_F1",
    characteristic: BLE_CONFIG.message,
    role: "forwarder",
  },
  F2: {
    name: "ShadowNet_F2",
    characteristic: BLE_CONFIG.message,
    role: "forwarder",
  },
  Gateway: {
    name: "ShadowNet_GW",
    characteristic: BLE_CONFIG.status,
    role: "gateway",
  },
};

// nodeId -> { deviceId, name, config, connected, manualDisconnect, properties }
const sessions = new Map();
const decoder = new TextDecoder();
const encoder = new TextEncoder();

let initPromise = null;

/**
 * Kept under the old name so App.jsx keeps working.
 * True inside the Android app, or in a browser with Web Bluetooth.
 */
export function isWebBluetoothAvailable() {
  if (Capacitor.isNativePlatform()) return true;

  return (
    typeof navigator !== "undefined" &&
    Boolean(navigator.bluetooth)
  );
}

export const isBluetoothAvailable = isWebBluetoothAvailable;

function getNodeConfig(nodeId) {
  const config = NODE_CONFIG[nodeId];

  if (!config) {
    throw new Error(`Unknown ShadowNet node: ${nodeId}`);
  }

  return config;
}

function decodeCharacteristicValue(dataView) {
  if (!dataView) return "";

  return decoder
    .decode(
      new Uint8Array(
        dataView.buffer,
        dataView.byteOffset,
        dataView.byteLength
      )
    )
    .replace(/\0+$/g, "")
    .trim();
}

function toDataView(bytes) {
  return new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  );
}

/**
 * Initializes the BLE plugin once (asks for Bluetooth permissions on
 * Android), then makes sure Bluetooth is switched on.
 */
async function ensureBluetoothReady() {
  if (!initPromise) {
    initPromise = BleClient.initialize({
      androidNeverForLocation: true,
    }).catch((error) => {
      initPromise = null;
      throw error;
    });
  }

  await initPromise;

  if (Capacitor.getPlatform() === "android") {
    const enabled = await BleClient.isEnabled();

    if (!enabled) {
      try {
        await BleClient.requestEnable();
      } catch {
        throw new Error(
          "Bluetooth is turned off. Turn it on and try again."
        );
      }
    }
  }
}

/**
 * Opens the Bluetooth device picker and connects
 * to the selected ShadowNet node.
 *
 * Call directly from a button click.
 */
export async function connectNode(
  nodeId,
  { onDisconnect } = {}
) {
  const config = getNodeConfig(nodeId);

  if (!isWebBluetoothAvailable()) {
    throw new Error(
      "Bluetooth is unavailable. Use the SadraNet Android app, or open this dashboard in Chrome or Edge on localhost/HTTPS."
    );
  }

  const existing = sessions.get(nodeId);

  if (existing?.connected) {
    return {
      device: { id: existing.deviceId, name: existing.name },
    };
  }

  await ensureBluetoothReady();

  const device = await BleClient.requestDevice({
    name: config.name,
    optionalServices: [BLE_CONFIG.service],
  });

  const session = {
    deviceId: device.deviceId,
    name: device.name || config.name,
    config,
    connected: false,
    manualDisconnect: false,
    properties: null,
  };

  sessions.set(nodeId, session);

  try {
    await BleClient.connect(device.deviceId, () => {
      session.connected = false;

      if (sessions.get(nodeId) === session) {
        sessions.delete(nodeId);
      }

      // disconnectNode() already updates the UI itself.
      if (!session.manualDisconnect) {
        onDisconnect?.(nodeId);
      }
    });

    // Check the expected service and characteristic exist,
    // like the Web Bluetooth version did.
    const services = await BleClient.getServices(device.deviceId);

    const service = services.find(
      (s) => s.uuid.toLowerCase() === BLE_CONFIG.service
    );

    if (!service) {
      throw new Error(
        `${nodeId} does not expose the ShadowNet service. Check the firmware UUIDs.`
      );
    }

    const characteristic = service.characteristics.find(
      (c) => c.uuid.toLowerCase() === config.characteristic
    );

    if (!characteristic) {
      throw new Error(
        `${nodeId} is missing the expected characteristic. Check the firmware UUIDs.`
      );
    }

    session.properties = characteristic.properties || {};
    session.connected = true;

    return {
      device: { id: device.deviceId, name: session.name },
    };
  } catch (error) {
    session.manualDisconnect = true;
    sessions.delete(nodeId);

    try {
      await BleClient.disconnect(device.deviceId);
    } catch {
      // Ignore cleanup errors.
    }

    throw error;
  }
}

export function isNodeConnected(nodeId) {
  return Boolean(sessions.get(nodeId)?.connected);
}

function getConnectedSession(nodeId) {
  const session = sessions.get(nodeId);

  if (!session?.connected) {
    throw new Error(`${nodeId} is not connected.`);
  }

  return session;
}

/**
 * Send a report note to F1 or F2.
 *
 * Current firmware uses GEO_REPORT=1.
 * Note field is limited to 8 bytes.
 */
export async function sendForwarderNote(nodeId, note) {
  if (nodeId !== "F1" && nodeId !== "F2") {
    throw new Error(
      "Choose F1 or F2. Gateway is a status monitor."
    );
  }

  const session = getConnectedSession(nodeId);

  const cleanNote = String(note ?? "").trim();

  if (!cleanNote) {
    throw new Error("Enter a report note first.");
  }

  const data = encoder.encode(cleanNote);

  if (data.length > 8) {
    throw new Error(
      `The current firmware note field is 8 bytes. Your note is ${data.length} bytes.`
    );
  }

  const props = session.properties || {};
  const value = toDataView(data);

  if (props.write) {
    await BleClient.write(
      session.deviceId,
      BLE_CONFIG.service,
      session.config.characteristic,
      value
    );
  } else if (props.writeWithoutResponse) {
    await BleClient.writeWithoutResponse(
      session.deviceId,
      BLE_CONFIG.service,
      session.config.characteristic,
      value
    );
  } else {
    throw new Error(
      "This BLE characteristic does not support writing."
    );
  }

  // BLE write confirmation, NOT LoRa delivery confirmation.
  return {
    acceptedByBle: true,
    note: cleanNote,
  };
}

/**
 * Read the Gateway's current status.
 */
export async function readGatewayStatus() {
  const session = getConnectedSession("Gateway");

  const value = await BleClient.read(
    session.deviceId,
    BLE_CONFIG.service,
    session.config.characteristic
  );

  return decodeCharacteristicValue(value);
}

/**
 * Subscribe to Gateway status notifications.
 * Returns an unsubscribe function.
 */
export async function subscribeGatewayStatus(onStatus) {
  const session = getConnectedSession("Gateway");
  const { deviceId } = session;
  const characteristic = session.config.characteristic;

  await BleClient.startNotifications(
    deviceId,
    BLE_CONFIG.service,
    characteristic,
    (value) => {
      onStatus(decodeCharacteristicValue(value));
    }
  );

  return async () => {
    try {
      await BleClient.stopNotifications(
        deviceId,
        BLE_CONFIG.service,
        characteristic
      );
    } catch {
      // It may already be disconnected.
    }
  };
}

/**
 * Disconnect a node.
 */
export function disconnectNode(nodeId) {
  const session = sessions.get(nodeId);

  if (!session) return;

  session.manualDisconnect = true;
  session.connected = false;
  sessions.delete(nodeId);

  BleClient.disconnect(session.deviceId).catch(() => {
    // It may already be disconnected.
  });
}