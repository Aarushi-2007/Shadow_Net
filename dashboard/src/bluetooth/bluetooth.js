
// ShadowNet BLE client.
// UUIDs and advertised names must match the ESP32 firmware.

export const BLE_CONFIG = {
  service: "12345678-1234-1234-1234-123456789000",
  message: "12345678-1234-1234-1234-123456789001",
  status: "12345678-1234-1234-1234-123456789002",
};

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

const sessions = new Map();
const decoder = new TextDecoder();
const encoder = new TextEncoder();

export function isWebBluetoothAvailable() {
  return (
    typeof navigator !== "undefined" &&
    Boolean(navigator.bluetooth)
  );
}

function getNodeConfig(nodeId) {
  const config = NODE_CONFIG[nodeId];

  if (!config) {
    throw new Error(`Unknown ShadowNet node: ${nodeId}`);
  }

  return config;
}

function decodeCharacteristicValue(dataView) {
  if (!dataView) return "";

  return decoder.decode(
    new Uint8Array(
      dataView.buffer,
      dataView.byteOffset,
      dataView.byteLength
    )
  ).replace(/\0+$/g, "").trim();
}

/**
 * Opens the browser BLE device picker and connects
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
      "Web Bluetooth is unavailable. Open this dashboard in Chrome or Edge on localhost/HTTPS."
    );
  }

  const existing = sessions.get(nodeId);

  if (
    existing?.device?.gatt?.connected &&
    existing.characteristic
  ) {
    return {
      device: existing.device,
      characteristic: existing.characteristic,
    };
  }

  const device = await navigator.bluetooth.requestDevice({
    filters: [{ name: config.name }],
    optionalServices: [BLE_CONFIG.service],
  });

  const disconnectHandler = () => {
    const current = sessions.get(nodeId);

    if (current?.device === device) {
      sessions.delete(nodeId);
    }

    onDisconnect?.(nodeId);
  };

  device.addEventListener(
    "gattserverdisconnected",
    disconnectHandler,
    { once: true }
  );

  try {
    const server = await device.gatt.connect();

    const service = await server.getPrimaryService(
      BLE_CONFIG.service
    );

    const characteristic =
      await service.getCharacteristic(
        config.characteristic
      );

    const session = {
      device,
      server,
      service,
      characteristic,
      config,
      disconnectHandler,
    };

    sessions.set(nodeId, session);

    return { device, characteristic };

  } catch (error) {
    try {
      if (device.gatt?.connected) {
        device.gatt.disconnect();
      }
    } catch {
      // Ignore cleanup errors.
    }

    throw error;
  }
}

export function isNodeConnected(nodeId) {
  return Boolean(
    sessions.get(nodeId)?.device?.gatt?.connected
  );
}

/**
 * Send a report note to F1 or F2.
 *
 * Current firmware uses GEO_REPORT=1.
 * Note field is limited to 8 bytes.
 */
export async function sendForwarderNote(
  nodeId,
  note
) {
  if (nodeId !== "F1" && nodeId !== "F2") {
    throw new Error(
      "Choose F1 or F2. Gateway is a status monitor."
    );
  }

  const session = sessions.get(nodeId);

  if (
    !session?.device?.gatt?.connected ||
    !session.characteristic
  ) {
    throw new Error(`${nodeId} is not connected.`);
  }

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

  const characteristic = session.characteristic;

  if (characteristic.writeValueWithResponse) {
    await characteristic.writeValueWithResponse(data);
  } else if (characteristic.writeValue) {
    await characteristic.writeValue(data);
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
  const session = sessions.get("Gateway");

  if (
    !session?.device?.gatt?.connected ||
    !session.characteristic
  ) {
    throw new Error("Gateway is not connected.");
  }

  const value =
    await session.characteristic.readValue();

  return decodeCharacteristicValue(value);
}

/**
 * Subscribe to Gateway status notifications.
 * Returns an unsubscribe function.
 */
export async function subscribeGatewayStatus(
  onStatus
) {
  const session = sessions.get("Gateway");

  if (
    !session?.device?.gatt?.connected ||
    !session.characteristic
  ) {
    throw new Error("Gateway is not connected.");
  }

  const characteristic = session.characteristic;

  const handler = (event) => {
    onStatus(
      decodeCharacteristicValue(event.target.value)
    );
  };

  await characteristic.startNotifications();

  characteristic.addEventListener(
    "characteristicvaluechanged",
    handler
  );

  return async () => {
    characteristic.removeEventListener(
      "characteristicvaluechanged",
      handler
    );

    try {
      await characteristic.stopNotifications();
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

  sessions.delete(nodeId);

  if (session.device?.gatt?.connected) {
    session.device.gatt.disconnect();
  }
}
