
import { useEffect, useMemo, useRef, useState } from "react";

import {
  connectNode,
  disconnectNode,
  isNodeConnected,
  isWebBluetoothAvailable,
  readGatewayStatus,
  sendForwarderNote,
  subscribeGatewayStatus,
} from "./bluetooth/bluetooth.js";

const INITIAL_NODES = [
  {
    id: "F1",
    label: "Forwarder 01",
    description: "Originates reports into the LoRa ring",
    bleName: "ShadowNet_F1",
    type: "forwarder",
  },
  {
    id: "F2",
    label: "Forwarder 02",
    description: "Originates reports into the LoRa ring",
    bleName: "ShadowNet_F2",
    type: "forwarder",
  },
  {
    id: "Gateway",
    label: "Gateway",
    description: "Receives LoRa reports and publishes status",
    bleName: "ShadowNet_GW",
    type: "gateway",
  },
];

function parseGatewayStatus(raw) {
  if (!raw) {
    return {
      title: "No gateway status yet",
      detail: "Connect to the gateway to read its current status.",
    };
  }

  const labels = {
    GATEWAY_ONLINE: "Gateway online",
    REPORT_RECEIVED: "Report received",
    PACKET_REJECTED: "Packet rejected",
    IDLE_CYCLE_OK: "Idle cycle completed",
    CYCLE_TIMEOUT: "Cycle timeout",
  };

  return {
    title: labels[raw] || raw,
    detail: raw,
    report: raw === "REPORT_RECEIVED",
  };
}

function NodeIcon({ type }) {
  return (
    <span className={`node-icon ${type === "gateway" ? "gateway-icon" : ""}`}>
      {type === "gateway" ? "⌂" : "⌁"}
    </span>
  );
}

export default function App() {
  const [nodes, setNodes] = useState(() =>
    Object.fromEntries(
      INITIAL_NODES.map((node) => [
        node.id,
        { connected: false, busy: false, deviceName: "" },
      ])
    )
  );

  const [selectedNode, setSelectedNode] = useState("F1");
  const [note, setNote] = useState("CHECKIN");
  const [sending, setSending] = useState(false);
  const [gatewayRaw, setGatewayRaw] = useState("");
  const [activity, setActivity] = useState([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const unsubscribeRef = useRef(null);

  const gatewayStatus = useMemo(
    () => parseGatewayStatus(gatewayRaw),
    [gatewayRaw]
  );

  const connectedCount = Object.values(nodes).filter(
    (node) => node.connected
  ).length;

  function addActivity(message, kind = "info") {
    setActivity((current) =>
      [
        {
          id: `${Date.now()}-${Math.random()}`,
          time: new Date().toLocaleTimeString(),
          message,
          kind,
        },
        ...current,
      ].slice(0, 8)
    );
  }

  function updateNode(nodeId, patch) {
    setNodes((current) => ({
      ...current,
      [nodeId]: { ...current[nodeId], ...patch },
    }));
  }

  async function handleConnect(nodeId) {
    setError("");
    setNotice("");

    updateNode(nodeId, { busy: true });

    try {
      const { device } = await connectNode(nodeId, {
        onDisconnect: (id) => {
          updateNode(id, {
            connected: false,
            busy: false,
            deviceName: "",
          });

          addActivity(`${id} disconnected`, "warning");

          if (id === "Gateway" && unsubscribeRef.current) {
            unsubscribeRef.current();
            unsubscribeRef.current = null;
          }
        },
      });

      updateNode(nodeId, {
        connected: true,
        busy: false,
        deviceName: device.name || "",
      });

      addActivity(`${nodeId} connected over BLE`, "success");

      if (nodeId === "Gateway") {
        const initial = await readGatewayStatus();

        setGatewayRaw(initial);
        addActivity(`Gateway status: ${initial}`, "info");

        const unsubscribe = await subscribeGatewayStatus((status) => {
          setGatewayRaw(status);

          addActivity(
            `Gateway update: ${status}`,
            status === "REPORT_RECEIVED" ? "success" : "info"
          );
        });

        unsubscribeRef.current = unsubscribe;
      }
    } catch (err) {
      updateNode(nodeId, {
        busy: false,
        connected: false,
      });

      setError(
        err?.message || "Could not connect to the selected node."
      );

      addActivity(
        `${nodeId}: ${err?.message || "connection failed"}`,
        "error"
      );
    }
  }

  function handleDisconnect(nodeId) {
    if (nodeId === "Gateway" && unsubscribeRef.current) {
      unsubscribeRef.current();
      unsubscribeRef.current = null;
    }

    disconnectNode(nodeId);

    updateNode(nodeId, {
      connected: false,
      busy: false,
      deviceName: "",
    });

    addActivity(`${nodeId} disconnected`, "warning");
  }

  async function handleSend(event) {
    event.preventDefault();

    setError("");
    setNotice("");
    setSending(true);

    try {
      const result = await sendForwarderNote(selectedNode, note);

      setNotice(
        `BLE write accepted by ${selectedNode}. The report is queued for its next normal LoRa cycle. This is not yet a delivery confirmation.`
      );

      addActivity(
        `Note "${result.note}" written to ${selectedNode} over BLE`,
        "success"
      );
    } catch (err) {
      setError(err?.message || "Could not send the report note.");
    } finally {
      setSending(false);
    }
  }

  useEffect(() => {
    return () => {
      if (unsubscribeRef.current) {
        unsubscribeRef.current();
      }

      for (const node of INITIAL_NODES) {
        disconnectNode(node.id);
      }
    };
  }, []);

  const bluetoothSupported = isWebBluetoothAvailable();

  const selectedConnected =
    isNodeConnected(selectedNode) &&
    nodes[selectedNode]?.connected;

  const noteBytes = new TextEncoder().encode(note).length;

  return (
    <main className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="topbar">
        <a className="brand" href="#top" aria-label="ShadowNet home">
          <span className="brand-mark">S</span>
          <span>
            <strong>SHADOWNET</strong>
            <small>FIELD CONTROL CENTER</small>
          </span>
        </a>

        <div className="topbar-right">
          <span className={`browser-pill ${bluetoothSupported ? "ok" : "bad"}`}>
            <i />
            {bluetoothSupported
              ? "Web Bluetooth available"
              : "Web Bluetooth unavailable"}
          </span>
          <span className="version-label">LOCAL CONSOLE · v1.0</span>
        </div>
      </header>

      <section className="hero" id="top">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            MESH NETWORK / LIVE OPERATIONS
          </div>

          <h1>
            ShadowNet <em>Control Center</em>
          </h1>

          <p>
            Connect to your field nodes, submit a report through a
            forwarder, and monitor what the gateway receives.
          </p>
        </div>

        <div className="hero-orbit" aria-hidden="true">
          <div className="orbit-ring ring-a" />
          <div className="orbit-ring ring-b" />
          <div className="orbit-core">SN</div>
          <span className="orbit-dot dot-a" />
          <span className="orbit-dot dot-b" />
          <span className="orbit-dot dot-c" />
        </div>
      </section>

      {!bluetoothSupported && (
        <div className="alert error-alert">
          Web Bluetooth is not available in this browser. Open this page
          in Chrome or Edge using localhost or HTTPS.
        </div>
      )}

      {error && (
        <div className="alert error-alert">
          <strong>Something went wrong</strong>
          <span>{error}</span>
          <button onClick={() => setError("")} aria-label="Dismiss error">
            ×
          </button>
        </div>
      )}

      <section className="section-block">
        <div className="section-heading">
          <div>
            <span className="section-index">01</span>
            <h2>Node connectivity</h2>
          </div>

          <div className="section-meta">
            <span className="live-dot" />
            {connectedCount} / 3 CONNECTED
          </div>
        </div>

        <div className="node-grid">
          {INITIAL_NODES.map((node, index) => {
            const state = nodes[node.id];

            return (
              <article
                className={`node-card ${state.connected ? "is-connected" : ""}`}
                key={node.id}
              >
                <div className="node-card-top">
                  <NodeIcon type={node.type} />

                  <span
                    className={`status-chip ${
                      state.connected ? "connected" : "disconnected"
                    }`}
                  >
                    <i />
                    {state.connected ? "CONNECTED" : "OFFLINE"}
                  </span>
                </div>

                <div className="node-number">NODE 0{index + 1}</div>
                <h3>{node.label}</h3>
                <p>{node.description}</p>

                <div className="node-ble-name">{node.bleName}</div>

                <button
                  className={`node-action ${
                    state.connected ? "secondary-action" : ""
                  }`}
                  disabled={!bluetoothSupported || state.busy}
                  onClick={() =>
                    state.connected
                      ? handleDisconnect(node.id)
                      : handleConnect(node.id)
                  }
                >
                  {state.busy ? (
                    <>
                      <span className="spinner" /> CONNECTING
                    </>
                  ) : state.connected ? (
                    "DISCONNECT"
                  ) : (
                    "CONNECT NODE"
                  )}
                </button>
              </article>
            );
          })}
        </div>

        <p className="helper-text">
          Each Connect button opens the browser Bluetooth device picker.
          Select the matching ShadowNet device.
        </p>
      </section>

      <section className="workspace-grid">
        <section className="panel send-panel">
          <div className="panel-heading">
            <div>
              <span className="section-index">02</span>
              <h2>Submit a field report</h2>
            </div>
            <span className="panel-icon">↗</span>
          </div>

          <p className="panel-description">
            Send a short report note to F1 or F2. The forwarder queues
            it for its next scheduled LoRa uplink.
          </p>

          <form onSubmit={handleSend}>
            <label htmlFor="forwarder">SOURCE FORWARDER</label>

            <div className="select-wrap">
              <select
                id="forwarder"
                value={selectedNode}
                onChange={(event) => setSelectedNode(event.target.value)}
              >
                <option value="F1">Forwarder 01 · F1</option>
                <option value="F2">Forwarder 02 · F2</option>
              </select>
              <span>⌄</span>
            </div>

            <div className="field-label-row">
              <label htmlFor="report-note">REPORT NOTE</label>
              <span
                className={`byte-count ${
                  noteBytes > 8 ? "over" : ""
                }`}
              >
                {noteBytes} / 8 BYTES
              </span>
            </div>

            <input
              id="report-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              maxLength={8}
              placeholder="e.g. CHECKIN"
              autoComplete="off"
            />

            <div className="input-hint">
              Current firmware uses GEO_REPORT=1. Note-only input
              preserves the node's configured position.
            </div>

            <button
              className="primary-action"
              type="submit"
              disabled={
                !selectedConnected ||
                sending ||
                !note.trim() ||
                noteBytes > 8
              }
            >
              {sending ? (
                <>
                  <span className="spinner" /> SENDING
                </>
              ) : (
                <>
                  SEND VIA BLE <span>→</span>
                </>
              )}
            </button>

            {!selectedConnected && (
              <div className="connect-reminder">
                Connect {selectedNode} above before sending a report.
              </div>
            )}
          </form>

          {notice && (
            <div className="alert success-alert">
              <strong>BLE write successful</strong>
              <span>{notice}</span>
              <button
                onClick={() => setNotice("")}
                aria-label="Dismiss notice"
              >
                ×
              </button>
            </div>
          )}
        </section>

        <section className="panel gateway-panel">
          <div className="panel-heading">
            <div>
              <span className="section-index">03</span>
              <h2>Gateway monitor</h2>
            </div>
            <span className="panel-icon">⌁</span>
          </div>

          <p className="panel-description">
            The gateway exposes a read/notify characteristic. It
            monitors LoRa reports; it does not originate user messages.
          </p>

          <div className="gateway-status-box">
            <div className="gateway-status-top">
              <span className="gateway-label">
                <i className="live-dot" /> LATEST GATEWAY STATUS
              </span>
              <span className="gateway-source">BLE / GATT</span>
            </div>

            <h3 className={gatewayStatus.report ? "report-title" : ""}>
              {gatewayStatus.title}
            </h3>

            <p>{gatewayStatus.detail}</p>

            {gatewayRaw && (
              <code className="raw-status">{gatewayRaw}</code>
            )}
          </div>

          <div className="gateway-actions">
            <button
              className="outline-action"
              disabled={!nodes.Gateway.connected}
              onClick={async () => {
                try {
                  const status = await readGatewayStatus();
                  setGatewayRaw(status);
                  addActivity(`Gateway read: ${status}`);
                } catch (err) {
                  setError(err.message);
                }
              }}
            >
              READ STATUS
            </button>

            <span className="notify-note">
              Notifications start automatically after Gateway connects.
            </span>
          </div>
        </section>
      </section>

      <section className="panel activity-panel">
        <div className="panel-heading">
          <div>
            <span className="section-index">04</span>
            <h2>Activity log</h2>
          </div>

          <button
            className="clear-button"
            onClick={() => setActivity([])}
          >
            CLEAR LOG
          </button>
        </div>

        {activity.length === 0 ? (
          <div className="empty-log">
            <span>◌</span>
            <div>
              <strong>No activity recorded</strong>
              <p>
                Connection events and gateway updates will appear here.
              </p>
            </div>
          </div>
        ) : (
          <div className="activity-list">
            {activity.map((entry) => (
              <div className="activity-row" key={entry.id}>
                <span className={`activity-marker ${entry.kind}`} />
                <time>{entry.time}</time>
                <span>{entry.message}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <footer className="footer">
        <span>SHADOWNET / LOCAL-FIRST FIELD INTERFACE</span>
        <span>
          BLE CONTROL PLANE <b>·</b> LORA DATA PLANE
        </span>
      </footer>
    </main>
  );
}
