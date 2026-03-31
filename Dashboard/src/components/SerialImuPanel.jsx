import { useState, useRef, useCallback } from "react";
import { clamp, quatToCss, parseCsvLine } from "../utils.js";

function ImuCube({ quat }) {
  const { qw = 1, qx = 0, qy = 0, qz = 0 } = quat || {};
  return (
    <div className="cube-scene">
      <div className="cube" style={{ transform: quatToCss(qw, qx, qy, qz) }}>
        <div className="face face-front">FRONT</div>
        <div className="face face-back">BACK</div>
        <div className="face face-right">RIGHT</div>
        <div className="face face-left">LEFT</div>
        <div className="face face-top">TOP</div>
        <div className="face face-bottom">BOT</div>
      </div>
    </div>
  );
}

export default function SerialImuPanel({ onImuUpdate }) {
  const [connected, setConnected] = useState(false);
  const [log,       setLog]       = useState([]);
  const [imu,       setImu]       = useState({ ax: 0, ay: 0, az: 0, qw: 1, qx: 0, qy: 0, qz: 0 });
  const portRef    = useRef(null);
  const readerRef  = useRef(null);
  const bufRef     = useRef("");

  const addLog = useCallback((msg, type = "dim") => {
    setLog((l) => [{ msg, type, id: Date.now() + Math.random() }, ...l].slice(0, 40));
  }, []);

  const connect = async () => {
    if (!("serial" in navigator)) {
      addLog("Web Serial not supported — use Chrome or Edge", "err");
      return;
    }
    try {
      const port = await navigator.serial.requestPort();
      await port.open({ baudRate: 115200 });
      portRef.current = port;
      setConnected(true);
      addLog("Connected at 115200 baud", "ok");
      readLoop(port);
    } catch (e) {
      addLog(`Connect failed: ${e.message}`, "err");
    }
  };

  const disconnect = async () => {
    try { readerRef.current?.cancel(); await portRef.current?.close(); } catch (_) {}
    portRef.current = null;
    readerRef.current = null;
    setConnected(false);
    addLog("Disconnected");
  };

  const readLoop = async (port) => {
    const decoder = new TextDecoderStream();
    port.readable.pipeTo(decoder.writable).catch(() => {});
    const reader = decoder.readable.getReader();
    readerRef.current = reader;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        bufRef.current += value;
        const lines = bufRef.current.split("\n");
        bufRef.current = lines.pop();
        for (const line of lines) {
          const t = line.trim();
          if (!t || t.startsWith("timestamp_ms")) continue;
          const p = parseCsvLine(t);
          if (p) {
            setImu(p);
            onImuUpdate?.(p);
          } else {
            addLog(t.slice(0, 60), "err");
          }
        }
      }
    } catch (e) {
      if (e.name !== "AbortError") addLog(`Read error: ${e.message}`, "err");
    }
    setConnected(false);
    addLog("Stream ended");
  };

  const channels = [
    { label: "AX", val: imu.ax, color: "#ff3a5c" },
    { label: "AY", val: imu.ay, color: "#39ff84" },
    { label: "AZ", val: imu.az, color: "#4fc3f7" },
  ];

  return (
    <div className="panel imu-panel">
      <div className="panel-header">
        <div className={`indicator ${connected ? "ind-green" : "ind-dim"}`} />
        <span className="panel-title">IMU · BNO085 · Serial</span>
        {connected && <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#39ff84" }}>115200</span>}
      </div>
      <div className="panel-body">
        <div className="imu-body">

          {/* Orientation cube */}
          <div className="imu-cube-section"><ImuCube quat={imu} /></div>

          {/* Linear acceleration */}
          <div className="imu-accel-section">
            <div className="section-title" style={{ marginBottom: 5, fontSize: 7 }}>LINEAR ACCEL (m/s²)</div>
            {channels.map(({ label, val, color }) => (
              <div className="imu-row" key={label}>
                <span className="imu-label">{label}</span>
                <div className="imu-bar-bg">
                  <div className="imu-bar-fill"
                    style={{ width: `${clamp((val / 20 + 0.5) * 100, 0, 100)}%`, background: color }} />
                </div>
                <span className="imu-val" style={{ color }}>{val.toFixed(4)}</span>
              </div>
            ))}
          </div>

          {/* Quaternion */}
          <div className="imu-quat-section">
            <div className="section-title" style={{ marginBottom: 5, fontSize: 7 }}>QUATERNION</div>
            <div className="quat-grid">
              {["qw", "qx", "qy", "qz"].map((k) => (
                <div className="quat-item" key={k}>
                  <span className="quat-key">{k.toUpperCase()}</span>
                  <span className="quat-val">{(imu[k] || 0).toFixed(5)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Serial controls + log */}
          <div className="imu-serial-section">
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              {!connected ? (
                <button className="btn" onClick={connect}>⟳ CONNECT SERIAL</button>
              ) : (
                <button className="btn danger" onClick={disconnect}>⏹ DISCONNECT</button>
              )}
            </div>
            <div className="serial-log">
              {log.length === 0 ? (
                <div className="serial-log-line" style={{ color: "#1a2540" }}>— no data —</div>
              ) : (
                log.map((l) => (
                  <div key={l.id} className={`serial-log-line ${l.type}`}>{l.msg}</div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}