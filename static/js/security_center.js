const BASE = "";

let activeFirewallRules = [];

// =========================
// 1. DYNAMIC INCIDENTS BOARD
// =========================
async function loadAlerts() {
  try {
    const res = await fetch(`${BASE}/api/alerts/?limit=30`);
    const data = await res.json();

    const table = document.getElementById("alertsTable");
    if (!table) return;

    if (data.length === 0) {
      table.innerHTML = `
        <tr>
          <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 40px;">
            No anomalies recorded. Host environment is secure.
          </td>
        </tr>
      `;
      return;
    }

    table.innerHTML = data.map(a => `
      <tr>
        <td>
          <span class="badge ${a.severity}">
            ${a.severity.toUpperCase()}
          </span>
        </td>
        <td class="table-alert-type" style="font-size:0.82rem; font-weight:700;">${a.alert_type}</td>
        <td class="table-ip" style="font-size:0.8rem;">${a.source_ip}</td>
        <td>
          ${a.resolved 
            ? '<span class="status-resolved">Resolved</span>' 
            : `<button class="resolve-btn" onclick="resolveAlert(${a.id})">Mitigate Incident</button>`
          }
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Error loading incidents:", err);
  }
}

async function resolveAlert(alertId) {
  try {
    const res = await fetch(`${BASE}/api/alerts/${alertId}/resolve`, {
      method: "PATCH"
    });
    if (res.ok) {
      await loadAlerts();
      await loadStats(); // Update threat index dial
      await loadFirewallRules(); // Reload policies list instantly on screen!
      console.log(`[MITIGATION] Defensive firewall containment deployed successfully for Alert ID ${alertId}.`);
    }
  } catch (err) {
    console.error("Error resolving incident:", err);
  }
}

// =========================
// 2. ACTIVE FIREWALL RULES
// =========================
async function loadFirewallRules() {
  try {
    const res = await fetch(`${BASE}/api/firewall/`);
    activeFirewallRules = await res.json();
    
    const container = document.getElementById("active-firewall-rules");
    if (!container) return;

    if (activeFirewallRules.length === 0) {
      container.innerHTML = `
        <div class="inspector-placeholder" style="grid-column: span 2; padding: 25px 0;">
          <p style="font-size: 0.76rem; color: var(--text-muted);">No custom blocks defined. Firewall is transparent.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = activeFirewallRules.map(r => `
      <div class="firewall-policy-item" style="background:#fafcff; border:1px solid var(--border-color); border-radius:8px; padding:10px 14px; display:flex; justify-content:space-between; align-items:center;">
        <div class="policy-meta-info" style="display:flex; flex-direction:column; gap:2px;">
          <span class="policy-badge" style="font-size:0.56rem; font-weight:800; color:var(--text-muted); text-transform:uppercase;">${r.rule_type}</span>
          <span class="policy-value" style="font-family:var(--font-mono); font-weight:700; font-size:0.8rem; color:var(--text-dark);">${r.value}</span>
        </div>
        <button class="policy-revoke-btn" onclick="revokeFirewallRule(${r.id})" title="Revoke block policy" style="background:transparent; border:none; cursor:pointer; font-size:0.95rem; color:var(--text-muted); transition:color 0.15s; padding:4px;">
          🗑️
        </button>
      </div>
    `).join("");

  } catch (err) {
    console.error("Error loading firewall rules:", err);
  }
}

window.revokeFirewallRule = async function(ruleId) {
  try {
    const res = await fetch(`${BASE}/api/firewall/${ruleId}`, {
      method: "DELETE"
    });
    if (res.ok) {
      await loadFirewallRules();
      await loadStats();
    }
  } catch (err) {
    console.error("Error revoking firewall rule:", err);
  }
};

// =========================
// 3. IRL THREAT INTEL BULLETINS
// =========================
async function loadThreatIntelFeed() {
  try {
    const res = await fetch(`${BASE}/api/stats/intel`);
    const data = await res.json();
    
    const feed = document.getElementById("intel-feed");
    if (!feed) return;

    if (data.length === 0) {
      feed.innerHTML = `
        <div class="inspector-placeholder">
          <p>No global threats recorded.</p>
        </div>
      `;
      return;
    }

    feed.innerHTML = data.map(bulletin => {
      let sevClass = "badge-low";
      if (bulletin.severity === "critical") sevClass = "badge critical";
      else if (bulletin.severity === "high") sevClass = "badge high";
      else if (bulletin.severity === "medium") sevClass = "badge medium";

      return `
        <div class="intel-item" style="border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; background: #fafcff; display: flex; flex-direction: column; gap: 6px; transition: all 0.2s;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span class="${sevClass}" style="font-size: 0.58rem; font-weight: 800;">${bulletin.severity.toUpperCase()}</span>
            <span style="font-size: 0.65rem; color: var(--text-muted); font-weight: 600;">${bulletin.date}</span>
          </div>
          <h4 style="font-family: var(--font-cyber); font-size: 0.8rem; font-weight: 800; color: var(--text-dark); line-height: 1.3;">
            ${bulletin.title}
          </h4>
          <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.45; word-break: break-word; margin-top: 2px;">
            ${bulletin.desc}
          </p>
          <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #f1f5f9; padding-top: 6px; margin-top: 4px; font-size: 0.65rem; font-weight: 600; color: var(--blue);">
            <span>Tag: ${bulletin.type}</span>
            <span style="color: var(--text-muted);">Source: ${bulletin.source}</span>
          </div>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error("Error loading threat intel:", err);
  }
}

// =========================
// 4. STATS MONITOR & THREAT INDEX DIAL
// =========================
async function loadStats() {
  try {
    const res = await fetch(`${BASE}/api/stats/`);
    const data = await res.json();

    const threatPercent = data.total_logs > 0 
      ? Math.min(Math.round((data.flagged_logs / data.total_logs) * 100), 100) 
      : 0;

    const fill = document.getElementById("threat-fill");
    if (fill) {
      fill.style.transform = `rotate(${threatPercent * 1.8}deg)`;
    }

    const percentageText = document.getElementById("threat-percentage");
    if (percentageText) {
      percentageText.innerText = `${threatPercent}%`;
    }

    const label = document.getElementById("threat-label");
    const badge = document.getElementById("threat-exposure-badge");

    if (label && badge) {
      if (threatPercent <= 3) {
        label.innerText = "SECURE";
        label.className = "threat-label secure";
        badge.innerText = "LOW THREAT LEVEL";
        badge.className = "badge low";
      } else if (threatPercent <= 12) {
        label.innerText = "MONITORED";
        label.className = "threat-label monitored";
        badge.innerText = "MODERATE THREAT";
        badge.className = "badge medium";
      } else if (threatPercent <= 25) {
        label.innerText = "ELEVATED";
        label.className = "threat-label elevated";
        badge.innerText = "ELEVATED EXPOSURE";
        badge.className = "badge high";
      } else {
        label.innerText = "CRITICAL";
        label.className = "threat-label critical";
        badge.innerText = "CRITICAL ALERT STATE";
        badge.className = "badge critical";
      }
    }
  } catch (err) {
    console.error("Error loading stats:", err);
  }
}

// =========================
// INITIALIZE
// =========================
async function init() {
  await loadFirewallRules();
  await loadAlerts();
  await loadStats();
  await loadThreatIntelFeed();

  // Active polling timers
  setInterval(loadFirewallRules, 4000);
  setInterval(loadAlerts, 5000);
  setInterval(loadStats, 3000);
  setInterval(loadThreatIntelFeed, 10000); // Poll IRL feeds occasionally
}

init();
