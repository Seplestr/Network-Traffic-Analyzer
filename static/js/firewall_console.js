const BASE = "";

let packetBytesBuffer = 0;
let capturedPackets = [];
let isCaptureActive = true; 
let currentSelectedRowIndex = -1;

// =========================
// WIRESHARK LIVE CAPTURE CONTROLS
// =========================
window.toggleStreamCapture = function() {
  const btn = document.getElementById("toggle-stream-btn");
  const dot = document.getElementById("stream-pulse-dot");
  const txt = document.getElementById("toggle-text");

  if (!btn) return;

  isCaptureActive = !isCaptureActive;

  if (isCaptureActive) {
    btn.classList.add("active-capture");
    dot.className = "btn-dot green";
    txt.innerText = "Capture Active";
  } else {
    btn.classList.remove("active-capture");
    dot.className = "btn-dot red";
    txt.innerText = "Capture Paused";
  }
};

window.clearPacketStream = function() {
  capturedPackets = [];
  currentSelectedRowIndex = -1;
  const wbody = document.getElementById("wireshark-tbody");
  if (wbody) {
    wbody.innerHTML = `
      <tr class="wireshark-placeholder">
        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 50px;">
          Waiting for active Windows socket connections... (Ensure live_sniffer.py is running)
        </td>
      </tr>
    `;
  }
  
  // Clear inspector panes
  const decodePane = document.getElementById("inspector-decode-pane");
  const hexPane = document.getElementById("inspector-hex-pane");
  
  if (decodePane) {
    decodePane.innerHTML = `
      <div class="inspector-placeholder">
        <p>Select a packet socket in the stream above to inspect fields.</p>
      </div>
    `;
  }
  if (hexPane) {
    hexPane.innerHTML = `
      <div class="inspector-placeholder">
        <p>Select a packet socket above to decode raw hexadecimal payload.</p>
      </div>
    `;
  }
};

// =========================
// TABLE STREAM LOCAL FILTER SEARCH
// =========================
window.filterStreamTable = function() {
  const query = document.getElementById("streamSearch").value.toLowerCase().trim();
  const rows = document.querySelectorAll("#wireshark-tbody .wireshark-row");

  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    if (text.includes(query)) {
      row.style.display = "";
    } else {
      row.style.display = "none";
    }
  });
};

// =========================
// DEEP PACKET INSPECTOR
// =========================
window.inspectPacket = function(index) {
  currentSelectedRowIndex = index;
  const log = capturedPackets[index];
  if (!log) return;

  // Row selection visual trigger
  const rows = document.querySelectorAll(".wireshark-row");
  rows.forEach(r => r.classList.remove("selected-row"));
  if (rows[index]) {
    rows[index].classList.add("selected-row");
  }

  const decodePane = document.getElementById("inspector-decode-pane");
  const hexPane = document.getElementById("inspector-hex-pane");

  const srcPort = log.source_port || 53612;
  const dstPort = log.dest_port || (log.protocol === 'TCP' ? 443 : 53);

  const mockSrcMac = `00:50:56:af:3c:${randomHexByte()}`;
  const mockDstMac = `00:0c:29:f2:a1:${randomHexByte()}`;

  // 1. GENERATE DECODED ACCORDION HEADERS
  decodePane.innerHTML = `
    <div class="dpi-header">FRAME ANALYSIS (Length: ${log.bytes_sent} Bytes)</div>
    
    <!-- DYNAMIC FIREWALL POLICY CONTROL (INTEGRATED ACCORDION) -->
    <details class="dpi-section" open>
      <summary class="dpi-section-title">Firewall Block Deployer</summary>
      <div class="dpi-section-content" style="padding: 10px;">
        <form id="firewall-rule-form" onsubmit="addFirewallRule(event)" style="display: flex; gap: 6px; width: 100%;">
          <select id="rule-type-select" style="flex: 1.1; padding: 6px; font-size: 0.72rem; border-radius: 6px; border: 1px solid var(--border-color); font-weight: 700; font-family: var(--font-cyber); background: #fafcff; outline: none;">
            <option value="app">Desktop App (.exe)</option>
            <option value="ip">IP Address</option>
            <option value="port">Port Number</option>
          </select>
          <input type="text" id="rule-value-input" value="${log.app_name || 'chrome.exe'}" required style="flex: 1.8; padding: 6px; font-size: 0.74rem; border-radius: 6px; border: 1px solid var(--border-color); font-family: var(--font-mono); outline: none;" />
          <button type="submit" class="resolve-btn" style="flex: 1.1; padding: 6px; font-size: 0.72rem; border-radius: 6px; background: var(--red); color: #fff; border-color: var(--red); font-weight: 700; cursor: pointer; transition: all 0.15s;">Deploy Block</button>
        </form>
      </div>
    </details>

    <details class="dpi-section" open>
      <summary class="dpi-section-title">Ethernet II Layer</summary>
      <div class="dpi-section-content">
        <div class="dpi-row"><span>Source MAC:</span><strong>${mockSrcMac}</strong></div>
        <div class="dpi-row"><span>Destination MAC:</span><strong>${mockDstMac}</strong></div>
        <div class="dpi-row"><span>Type:</span><strong>IPv4 (0x0800)</strong></div>
      </div>
    </details>

    <details class="dpi-section" open>
      <summary class="dpi-section-title">Internet Protocol Version 4</summary>
      <div class="dpi-section-content">
        <div class="dpi-row"><span>Source IP:</span><strong>${log.source_ip}</strong></div>
        <div class="dpi-row"><span>Destination IP:</span><strong>${log.dest_ip}</strong></div>
        <div class="dpi-row"><span>Header Length:</span><strong>20 Bytes</strong></div>
        <div class="dpi-row"><span>TTL Hop Count:</span><strong>${log.flagged ? 64 : 128}</strong></div>
        <div class="dpi-row"><span>Total Length:</span><strong>${log.bytes_sent} Bytes</strong></div>
      </div>
    </details>

    <details class="dpi-section" open>
      <summary class="dpi-section-title">${log.protocol} Transport Layer</summary>
      <div class="dpi-section-content">
        <div class="dpi-row"><span>Source Port:</span><strong>${srcPort}</strong></div>
        <div class="dpi-row"><span>Destination Port:</span><strong>${dstPort}</strong></div>
        ${log.protocol === 'TCP' ? `
          <div class="dpi-row"><span>Seq:</span><strong>${randomSeqNum()}</strong></div>
          <div class="dpi-row"><span>Flags:</span><strong>${log.flagged ? '0x002 (SYN)' : '0x018 (PSH, ACK)'}</strong></div>
        ` : ''}
      </div>
    </details>
  `;

  // 2. GENERATE DETAILED INTERACTIVE HEX/ASCII HIGHLIGHT EDITOR
  hexPane.innerHTML = generateInteractiveHexDump(log);
};

// =========================
// DYNAMIC FIREWALL DEPLOYER
// =========================
window.addFirewallRule = async function(event) {
  event.preventDefault();
  const select = document.getElementById("rule-type-select");
  const input = document.getElementById("rule-value-input");
  if (!select || !input) return;

  const rule_type = select.value;
  const value = input.value.trim();

  if (!value) return;

  try {
    const res = await fetch(`${BASE}/api/firewall/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_type, value, action: "block" })
    });

    if (res.ok) {
      alert(`Firewall successfully deployed block policy for ${rule_type}='${value}'!`);
      input.value = "";
    } else {
      const errData = await res.json();
      alert(errData.detail || "Failed to add firewall rule");
    }
  } catch (err) {
    console.error("Error adding firewall rule:", err);
  }
};

// =========================
// INTERACTIVE HEX EDITOR MOUSE HOVER HIGHLIGHT
// =========================
function generateInteractiveHexDump(log) {
  const bytesCount = Math.min(Math.round(log.bytes_sent), 128); 
  const bytes = [];
  
  for (let i = 0; i < bytesCount; i++) {
    let b = Math.floor(Math.random() * 256);
    if (i < 40 && log.protocol === 'TCP') {
      const standardPayload = "GET /api/v1/telemetry HTTP/1.1\r\nHost: target\r\nUser-Agent: PCFirewall\r\n";
      b = standardPayload.charCodeAt(i % standardPayload.length);
    }
    bytes.push(b);
  }

  let html = `<div class="hex-dump-console"><div class="hex-dump-editor">`;

  for (let i = 0; i < bytesCount; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(4, '0');
    
    let bytesHtml = "";
    let asciiHtml = "";

    chunk.forEach((b, idx) => {
      const absoluteIndex = i + idx;
      const bHex = b.toString(16).padStart(2, '0');
      const bChar = (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';

      bytesHtml += `<span class="hex-byte" data-hex-index="${absoluteIndex}" onmouseover="hoverByte(${absoluteIndex}, true)" onmouseout="hoverByte(${absoluteIndex}, false)">${bHex}</span> `;
      
      const charSafe = bChar === '<' ? '&lt;' : (bChar === '>' ? '&gt;' : bChar);
      asciiHtml += `<span class="hex-char" data-ascii-index="${absoluteIndex}" onmouseover="hoverByte(${absoluteIndex}, true)" onmouseout="hoverByte(${absoluteIndex}, false)">${charSafe}</span>`;
    });

    html += `
      <div class="hex-dump-line">
        <span class="hex-offset">${offset}</span>
        <span class="hex-bytes-group">${bytesHtml.padEnd(48, ' ')}</span>
        <span class="hex-ascii-group">${asciiHtml}</span>
      </div>
    `;
  }

  html += `</div></div>`;
  return html;
}

window.hoverByte = function(index, isActive) {
  const byteNode = document.querySelector(`[data-hex-index="${index}"]`);
  const charNode = document.querySelector(`[data-ascii-index="${index}"]`);

  if (isActive) {
    if (byteNode) byteNode.classList.add("hover-active");
    if (charNode) charNode.classList.add("hover-active");
  } else {
    if (byteNode) byteNode.classList.remove("hover-active");
    if (charNode) charNode.classList.remove("hover-active");
  }
};

function randomHexByte() {
  return Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
}

function randomSeqNum() {
  return Math.floor(Math.random() * 100000000) + 120531;
}

// =========================
// CORE WEBSOCKET CHANNEL
// =========================
function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${protocol}://${window.location.host}/ws/live-traffic`);

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    const bytesVal = Number(data.bytes_sent);

    if (!isCaptureActive) return;

    const srcPort = data.source_port || 53612;
    const dstPort = data.dest_port || (data.protocol === 'TCP' ? 443 : 53);

    // Prepend to Captured Arrays
    capturedPackets.unshift(data);
    if (capturedPackets.length > 50) {
      capturedPackets.pop();
    }

    const wbody = document.getElementById("wireshark-tbody");
    if (wbody) {
      const placeholder = wbody.querySelector(".wireshark-placeholder");
      if (placeholder) placeholder.remove();

      const newRow = document.createElement("tr");
      newRow.className = `wireshark-row ${data.flagged ? 'flagged-row' : ''}`;
      newRow.setAttribute("onclick", `inspectPacket(0)`);

      // Adjust index offsets on active nodes
      const activeRows = wbody.getElementsByClassName("wireshark-row");
      for (let i = 0; i < activeRows.length; i++) {
        activeRows[i].setAttribute("onclick", `inspectPacket(${i + 1})`);
      }

      const now = new Date().toLocaleTimeString();

      // Beautiful visual styling for common processes
      let appBadge = `<span style="font-weight:700; color:var(--text-dark);">${data.app_name || 'SYSTEM'}</span>`;
      if (data.app_name) {
        const lowerApp = data.app_name.toLowerCase();
        if (lowerApp.includes("chrome")) {
          appBadge = `<span class="badge" style="background:#eff6ff; color:#1e40af; border:1px solid #bfdbfe;">🌐 chrome.exe</span>`;
        } else if (lowerApp.includes("python")) {
          appBadge = `<span class="badge" style="background:#f0fdf4; color:#166534; border:1px solid #bbf7d0;">🐍 python.exe</span>`;
        } else if (lowerApp.includes("discord")) {
          appBadge = `<span class="badge" style="background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe;">👾 discord.exe</span>`;
        }
      }

      newRow.innerHTML = `
        <td style="color:var(--text-muted); font-size:0.7rem;">${now}</td>
        <td>${appBadge}</td>
        <td class="table-ip">${data.source_ip}:${srcPort}</td>
        <td class="table-ip">${data.dest_ip}:${dstPort}</td>
        <td>
          <span class="badge" style="background:#f8fafc; color:#475569; border:1px solid var(--border-color);">
            ${data.protocol}
          </span>
        </td>
        <td style="font-weight:600;">${bytesVal.toLocaleString()} B</td>
        <td>
          <span class="badge ${data.action === 'block' ? 'critical' : 'low'}">
            ${data.action === 'block' ? 'BLOCK' : 'ALLOW'}
          </span>
        </td>
      `;

      wbody.insertBefore(newRow, wbody.firstChild);

      if (wbody.children.length > 50) {
        wbody.removeChild(wbody.lastChild);
      }
      
      // Auto-inspect first packet to keep inspectors populated
      if (wbody.children.length === 1) {
        inspectPacket(0);
      }
    }

    // Apply filter
    filterStreamTable();
  };
}

initWebSocket();
