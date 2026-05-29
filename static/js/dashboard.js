const BASE = "";

let trafficChart;
let protocolChart;
let packetBytesBuffer = 0;

// =========================
// LOAD METRIC INDEX STATS
// =========================
async function loadStats() {
  try {
    const res = await fetch(`${BASE}/api/stats/`);
    const data = await res.json();

    document.getElementById("s-total").innerText = data.total_logs;
    document.getElementById("s-flagged").innerText = data.flagged_logs;
    document.getElementById("s-alerts").innerText = data.total_alerts;

    // Active Firewall Policies count from database
    const resRules = await fetch(`${BASE}/api/firewall/`);
    const activeRules = await resRules.json();
    document.getElementById("s-unresolved").innerText = activeRules.length;

    // Dynamic Threat Severity Index Dial
    const threatPercent = data.total_logs > 0 
      ? Math.min(Math.round((data.flagged_logs / data.total_logs) * 100), 100) 
      : 0;

    document.getElementById("threat-percentage").innerText = `${threatPercent}%`;

    const fill = document.getElementById("threat-fill");
    if (fill) {
      fill.style.transform = `rotate(${threatPercent * 1.8}deg)`;
    }

    const label = document.getElementById("threat-label");
    if (label) {
      if (threatPercent <= 3) {
        label.innerText = "SECURE";
        label.className = "threat-label secure";
      } else if (threatPercent <= 12) {
        label.innerText = "MONITORED";
        label.className = "threat-label monitored";
      } else if (threatPercent <= 25) {
        label.innerText = "ELEVATED";
        label.className = "threat-label elevated";
      } else {
        label.innerText = "CRITICAL";
        label.className = "threat-label critical";
      }
    }

    updateProtocolChart(data.protocol_breakdown);

    // Populating Top Source IPs Ingestion Table
    const topIpsTable = document.getElementById("top-ips-tbody");
    if (topIpsTable) {
      if (data.top_source_ips.length === 0) {
        topIpsTable.innerHTML = `<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 20px;">No source hosts recorded.</td></tr>`;
      } else {
        topIpsTable.innerHTML = data.top_source_ips.map(ipData => `
          <tr>
            <td class="table-ip" style="font-size:0.78rem; padding: 8px;">${ipData.ip}</td>
            <td style="text-align: right; font-weight: 700; color: var(--blue); font-size:0.8rem; padding: 8px;">${ipData.count}</td>
          </tr>
        `).join("");
      }
    }

    // Populating Top Target Ingress Ports Table
    const topPortsTable = document.getElementById("top-ports-tbody");
    if (topPortsTable) {
      if (data.top_dest_ports.length === 0) {
        topPortsTable.innerHTML = `<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 20px;">No destinations recorded.</td></tr>`;
      } else {
        topPortsTable.innerHTML = data.top_dest_ports.map(portData => {
          let service = "";
          const port = Number(portData.port);
          if (port === 80) service = " (HTTP)";
          else if (port === 443) service = " (HTTPS)";
          else if (port === 53) service = " (DNS)";
          else if (port === 3306) service = " (MySQL)";
          else if (port === 22) service = " (SSH)";
          else if (port === 23) service = " (Telnet)";

          return `
            <tr>
              <td style="font-family: var(--font-mono); font-weight: 600; font-size:0.78rem; padding: 8px; color: var(--text-dark);">${port}${service}</td>
              <td style="text-align: right; font-weight: 700; color: var(--orange); font-size:0.8rem; padding: 8px;">${portData.count}</td>
            </tr>
          `;
        }).join("");
      }
    }

  } catch (err) {
    console.error("Error loading SOC stats:", err);
  }
}

// =========================
// LINE CHART INITS
// =========================
function initTrafficChart() {
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;

  const gradientCtx = ctx.getContext('2d');
  const gradient = gradientCtx.createLinearGradient(0, 0, 0, 200);
  gradient.addColorStop(0, 'rgba(37, 99, 235, 0.16)');
  gradient.addColorStop(1, 'rgba(37, 99, 235, 0.00)');

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: Array(15).fill(""),
      datasets: [{
        data: Array(15).fill(0),
        borderColor: '#2563eb', 
        backgroundColor: gradient,
        fill: true,
        tension: 0.4,
        borderWidth: 2,
        pointRadius: 2,
        pointBackgroundColor: '#2563eb'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 150 },
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { display: false }, grid: { display: false } },
        y: { beginAtZero: true, ticks: { color: '#64748b', font: { size: 9 } }, grid: { color: '#f1f5f9' } }
      }
    }
  });

  // Ticker to slide throughput values in real-time
  setInterval(() => {
    if (!trafficChart) return;
    const now = new Date().toLocaleTimeString();

    trafficChart.data.labels.push(now);
    trafficChart.data.datasets[0].data.push(packetBytesBuffer);

    if (trafficChart.data.labels.length > 15) {
      trafficChart.data.labels.shift();
      trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.update();
    packetBytesBuffer = 0;
  }, 1000);

  // =========================
  // CORE WEBSOCKET PIPELINE
  // =========================
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${protocol}://${window.location.host}/ws/live-traffic`);

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    const bytesVal = Number(data.bytes_sent);
    packetBytesBuffer += bytesVal;
    
    // Smooth counters reload
    loadStats();
  };

  ws.onerror = (err) => {
    console.error("SOC Ingestion WebSocket Error", err);
  };
}

// =========================
// PROTOCOL DOUGHNUT
// =========================
function updateProtocolChart(protocols) {
  const ctx = document.getElementById('protocolChart');
  if (!ctx) return;

  if (protocolChart) {
    protocolChart.data.labels = protocols.map(p => p.protocol);
    protocolChart.data.datasets[0].data = protocols.map(p => p.count);
    protocolChart.update();
  } else {
    protocolChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: protocols.map(p => p.protocol),
        datasets: [{
          data: protocols.map(p => p.count),
          backgroundColor: ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#6366f1'],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#64748b', font: { size: 10 }, boxWidth: 8, padding: 8 }
          }
        },
        cutout: '75%'
      }
    });
  }
}

// =========================
// INITIALIZE
// =========================
async function init() {
  await loadStats();
  initTrafficChart();

  // Background metric poller
  setInterval(loadStats, 3000);
}

init();