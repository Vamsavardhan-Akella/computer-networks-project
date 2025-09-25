// Network Discovery MVP Dashboard JavaScript

// Initialize Socket.IO connection
const socket = io();

// Initialize Cytoscape
let cy;
let devices = {};
let autoScanEnabled = false;
let nextScanTime = null;
let countdownInterval = null;

// DOM elements
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const autoScanBtn = document.getElementById("autoScanBtn");
const intervalInput = document.getElementById("intervalInput");
const statusMessage = document.getElementById("statusMessage");
const loading = document.getElementById("loading");
const deviceCount = document.getElementById("deviceCount");
const lastScan = document.getElementById("lastScan");
const scanStatus = document.getElementById("scanStatus");
const deviceList = document.getElementById("deviceList");
const autoScanStatus = document.getElementById("autoScanStatus");
// Add Speed Test button dynamically into controls if not present
document.addEventListener("DOMContentLoaded", function () {
  const controls = document.querySelector('.controls');
  if (controls && !document.getElementById('speedBtn')) {
    const btn = document.createElement('button');
    btn.id = 'speedBtn';
    btn.className = 'btn';
    btn.textContent = 'Speed Test';
    btn.addEventListener('click', function(){
      socket.emit('speed_test');
      statusMessage.textContent = 'Running speed test...';
    });
    controls.appendChild(btn);
  }
});

const autoScanStatusText = document.getElementById("autoScanStatusText");
const autoScanInterval = document.getElementById("autoScanInterval");
const intervalDisplay = document.getElementById("intervalDisplay");
const nextScanDisplay = document.getElementById("nextScanDisplay");
const nextScanTimeElement = document.getElementById("nextScanTime");
let bandwidth = {}; // ip -> { rate_in_bps, rate_out_bps }

// Initialize Cytoscape graph
function initGraph() {
  cy = cytoscape({
    container: document.getElementById("cy"),

    style: [
      {
        selector: "node",
        style: {
          "background-color": "#4CAF50",
          label: "data(label)",
          color: "white",
          "text-valign": "center",
          "text-halign": "center",
          "font-size": "12px",
          width: 40,
          height: 40,
          "border-width": 2,
          "border-color": "white",
          "overlay-opacity": 0,
        },
      },
      {
        selector: 'node[type="router"]',
        style: {
          "background-color": "#FF9800",
          shape: "diamond",
          width: 50,
          height: 50,
        },
      },
      {
        selector: 'node[type="unknown"]',
        style: {
          'background-color': '#616161',
        },
      },
      {
        selector: 'node[type="hotspot_gateway"]',
        style: {
          "background-color": "#FF6F00",
          shape: "diamond",
          width: 45,
          height: 45,
          "border-width": 3,
        },
      },
      {
        selector: 'node[type="computer"]',
        style: {
          "background-color": "#2196F3",
          shape: "rectangle",
          width: 45,
          height: 35,
        },
      },
      {
        selector: 'node[type="mobile"]',
        style: {
          "background-color": "#E91E63",
          shape: "ellipse",
          width: 35,
          height: 45,
        },
      },
      {
        selector: 'node[type="mobile_hotspot"]',
        style: {
          "background-color": "#9C27B0",
          shape: "ellipse",
          width: 40,
          height: 50,
          "border-width": 3,
          "border-style": "dashed",
        },
      },
      {
        selector: 'node[type="printer"]',
        style: {
          "background-color": "#607D8B",
          shape: "rectangle",
          width: 40,
          height: 30,
        },
      },
      {
        selector: 'node[type="media"]',
        style: {
          "background-color": "#795548",
          shape: "rectangle",
          width: 50,
          height: 30,
        },
      },
      {
        selector: 'node[type="iot"]',
        style: {
          "background-color": "#009688",
          shape: "triangle",
          width: 30,
          height: 30,
        },
      },
      {
        selector: 'node[type="nas"]',
        style: {
          "background-color": "#3F51B5",
          shape: "rectangle",
          width: 45,
          height: 40,
        },
      },
      {
        selector: 'node[type="virtual"]',
        style: {
          "background-color": "#9E9E9E",
          shape: "hexagon",
          width: 35,
          height: 35,
          opacity: 0.7,
        },
      },
    ],

    layout: {
      name: "cose",
      idealEdgeLength: 100,
      nodeOverlap: 20,
      refresh: 20,
      fit: true,
      padding: 30,
      randomize: false,
      componentSpacing: 100,
      nodeRepulsion: 400000,
      edgeElasticity: 100,
      nestingFactor: 5,
      gravity: 80,
      numIter: 1000,
      initialTemp: 200,
      coolingFactor: 0.95,
      minTemp: 1.0,
    },
  });

  // Add click handler for nodes
  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    const device = devices[node.id()];
    if (device) {
      const ports = (device.open_ports || [])
        .map(p => `${p.proto || 'tcp'}/${p.port}${p.name ? ' ('+p.name+')' : ''}`)
        .join(', ');
      const vulns = (device.vulnerabilities || []).join(', ');
      const lines = [
        `Device: ${device.hostname || 'Unknown'}`,
        `IP: ${device.ip}`,
        `Type: ${device.type || 'unknown'}`,
        `Status: ${device.status || 'unknown'}`,
        `MAC: ${device.mac_address || 'N/A'}`,
        `Vendor: ${device.vendor || 'N/A'}`,
        `OS: ${device.os || 'Unknown'}`,
        `Open Ports: ${ports || 'None'}`,
        `Vulns: ${vulns || 'None'}`,
      ];
      alert(lines.join('\n'));
    }
  });

  // Simple grouping by type using concentric layout weights
  cy.on('layoutstop', function(){
    // No-op placeholder; layout already applied after updates
  });
}

// Socket.IO event handlers
socket.on("connect", function () {
  console.log("Connected to server");
  statusMessage.textContent = "Connected";
  // Request current devices snapshot on connect
  try { socket.emit('get_devices'); } catch (e) { console.error(e); }
});

socket.on("status", function (data) {
  console.log("Status:", data.message);
  statusMessage.textContent = data.message;
  scanStatus.textContent = data.message.includes("Scan")
    ? "Scanning"
    : "Idle";

  if (data.message.includes("started")) {
    loading.style.display = "block";
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
  } else if (data.message.includes("complete")) {
    loading.style.display = "none";
    scanBtn.disabled = false;
    scanBtn.textContent = "Start Scan";
    lastScan.textContent = new Date().toLocaleTimeString();
    scanStatus.textContent = "Complete";
  }
});

socket.on("devices_update", function (data) {
  console.log("Devices update:", data.devices);
  if (!cy) { initGraph(); }
  devices = data.devices;
  updateGraph();
  updateDeviceList();
  updateStats();

  // Update last scan time
  if (data.timestamp) {
    lastScan.textContent = new Date(
      data.timestamp * 1000
    ).toLocaleTimeString();
  }
});

socket.on('notification', function (data) {
  if (!data) return;
  if (data.type === 'join' && data.ips && data.ips.length) {
    statusMessage.textContent = `New device(s) joined: ${data.ips.join(', ')}`;
  } else if (data.type === 'leave' && data.ips && data.ips.length) {
    statusMessage.textContent = `Device(s) left: ${data.ips.join(', ')}`;
  }
});

socket.on('speed_test_result', function (data) {
  if (!data) return;
  const gw = data.gateway;
  const inet = data.internet;
  const msg = `Speed Test: gateway ${gw ? gw.latency_ms+'ms' : 'n/a'}, internet ${inet ? inet.latency_ms+'ms' : 'n/a'}`;
  statusMessage.textContent = msg;
});

socket.on('bandwidth_update', function (data) {
  bandwidth = data || {};
  updateDeviceList();
});

socket.on("auto_scan_status", function (data) {
  console.log("Auto-scan status:", data);
  autoScanEnabled = data.enabled;
  nextScanTime = data.next_scan;

  updateAutoScanUI(data);

  if (autoScanEnabled && nextScanTime) {
    startCountdown();
  } else {
    stopCountdown();
  }
});

function updateAutoScanUI(data) {
  const isActive = data.enabled;

  // Update button state
  autoScanBtn.textContent = isActive ? "Stop Auto-Scan" : "Auto-Scan";
  autoScanBtn.classList.toggle("active", isActive);

  // Update status display
  autoScanStatus.classList.toggle("active", isActive);
  autoScanStatusText.textContent = isActive ? "Enabled" : "Disabled";

  if (isActive) {
    intervalDisplay.style.display = "flex";
    nextScanDisplay.style.display = "block";
    autoScanInterval.textContent = data.interval + "s";
    intervalInput.value = data.interval;
  } else {
    intervalDisplay.style.display = "none";
    nextScanDisplay.style.display = "none";
  }
}

function startCountdown() {
  stopCountdown(); // Clear any existing countdown

  countdownInterval = setInterval(() => {
    if (nextScanTime && autoScanEnabled) {
      const now = Date.now() / 1000;
      const remaining = nextScanTime - now;

      if (remaining > 0) {
        const minutes = Math.floor(remaining / 60);
        const seconds = Math.floor(remaining % 60);
        nextScanTimeElement.textContent = `${minutes}m ${seconds
          .toString()
          .padStart(2, "0")}s`;
      } else {
        nextScanTimeElement.textContent = "Starting...";
      }
    }
  }, 1000);
}

function stopCountdown() {
  if (countdownInterval) {
    clearInterval(countdownInterval);
    countdownInterval = null;
  }
  nextScanTimeElement.textContent = "--";
}

// Update graph visualization
function updateGraph() {
  if (!cy) return;

  // Clear existing elements
  cy.elements().remove();

  // Add nodes for devices
  Object.values(devices).forEach((device) => {
    cy.add({
      group: "nodes",
      data: {
        id: device.ip,
        label: device.hostname || device.ip,
        type: device.type || "unknown",
        weight: device.type === 'router' || device.type === 'hotspot_gateway' ? 3 : 1,
      },
    });
  });

  // Add edges (for MVP, connect all to router if exists)
  const routerIp = Object.keys(devices).find(
    (ip) =>
      devices[ip].type === "router" ||
      devices[ip].type === "hotspot_gateway"
  );
  if (routerIp) {
    Object.keys(devices).forEach((ip) => {
      if (ip !== routerIp) {
        cy.add({
          group: "edges",
          data: {
            id: `${routerIp}-${ip}`,
            source: routerIp,
            target: ip,
          },
        });
      }
    });
  }

  // Run layout
  const typeClusters = {};
  Object.values(devices).forEach((d) => { typeClusters[d.type || 'unknown'] = true; });
  cy.layout({
    name: "concentric",
    concentric: function(node){ return node.data('weight') || 1; },
    levelWidth: function(){ return 1; },
    padding: 30,
    animate: true,
    fit: true,
  }).run();
}

// Update device list in sidebar with enhanced type detection
function updateDeviceList() {
  const deviceArray = Object.values(devices);

  if (deviceArray.length === 0) {
    deviceList.innerHTML = `
      <div style="text-align: center; opacity: 0.6; margin-top: 2rem;">
          No devices discovered yet.<br>
          Click "Start Scan" to begin.
      </div>
    `;
    return;
  }

  // Device type icons and descriptions
  const deviceIcons = {
    router: "🌐",
    hotspot_gateway: "📶",
    computer: "💻",
    mobile: "📱",
    mobile_hotspot: "📶",
    printer: "🖨️",
    media: "📺",
    iot: "🏠",
    nas: "💾",
    virtual: "🖥️",
    unknown: "❓",
  };

  const deviceDescriptions = {
    router: "Network Router",
    hotspot_gateway: "Mobile Hotspot Gateway",
    computer: "Computer/Laptop",
    mobile: "Mobile Device",
    mobile_hotspot: "Mobile Device (Hotspot)",
    printer: "Network Printer",
    media: "Media Device",
    iot: "IoT/Smart Device",
    nas: "Network Storage",
    virtual: "Virtual Machine",
    unknown: "Unknown Device",
  };

  deviceList.innerHTML = deviceArray
    .sort((a, b) => {
      // Sort by type priority, then by IP
      const typePriority = {
        router: 1,
        hotspot_gateway: 2,
        computer: 3,
        mobile: 4,
        mobile_hotspot: 5,
        printer: 6,
        media: 7,
        iot: 8,
        nas: 9,
        virtual: 10,
        unknown: 99,
      };

      const priorityDiff =
        (typePriority[a.type] || 99) - (typePriority[b.type] || 99);
      if (priorityDiff !== 0) return priorityDiff;

      // Secondary sort by IP (last octet)
      const aIP = parseInt(a.ip.split(".").pop());
      const bIP = parseInt(b.ip.split(".").pop());
      return aIP - bIP;
    })
    .map(
      (device) => `
        <div class="device-item">
            <div class="device-header">
                <span class="device-icon">${
                  deviceIcons[device.type] || deviceIcons.unknown
                }</span>
                <span class="device-ip">${device.ip}</span>
            </div>
            <div class="device-hostname">${
              device.hostname || "Unknown Hostname"
            }</div>
            <div class="device-type">${
              deviceDescriptions[device.type] || device.type
            }</div>
            <div class="device-status status-${device.status}">${device.status}</div>
            ${(() => { 
              const bw = bandwidth[device.ip];
              if (!bw) return '';
              const inMbps = (bw.rate_in_bps || 0) / 1e6;
              const outMbps = (bw.rate_out_bps || 0) / 1e6;
              return `<div class="device-bw">⬇ ${inMbps.toFixed(2)} Mbps • ⬆ ${outMbps.toFixed(2)} Mbps</div>`;
            })()}
            ${
              device.mac_address
                ? `<div class="device-mac">MAC: ${device.mac_address}</div>`
                : ""
            }
        </div>
      `
    )
    .join("");
}

// Update stats
function updateStats() {
  deviceCount.textContent = Object.keys(devices).length;
}

// Event listeners
scanBtn.addEventListener("click", function () {
  socket.emit("start_scan");
});

autoScanBtn.addEventListener("click", function () {
  const interval = parseInt(intervalInput.value) || 60;

  socket.emit("toggle_auto_scan", {
    enabled: !autoScanEnabled,
    interval: interval,
  });
});

intervalInput.addEventListener("change", function () {
  if (autoScanEnabled) {
    const interval = parseInt(this.value) || 60;
    socket.emit("toggle_auto_scan", {
      enabled: true,
      interval: interval,
    });
  }
});

clearBtn.addEventListener("click", function () {
  // Reset devices
  devices = {};

  // Clear graph
  if (cy) {
    cy.elements().remove();
  }

  // Reset UI elements
  updateDeviceList();
  updateStats();

  // Reset status and buttons
  statusMessage.textContent = "Cleared - Ready to scan";
  scanStatus.textContent = "Idle";
  lastScan.textContent = "Never";
  loading.style.display = "none";

  // Ensure scan button is properly reset
  scanBtn.disabled = false;
  scanBtn.textContent = "Start Scan";
  scanBtn.classList.add("primary");

  console.log("Dashboard cleared");
});

// Initialize when page loads
document.addEventListener("DOMContentLoaded", function () {
  initGraph();
  console.log("Network Discovery MVP Dashboard with Auto-Scan loaded");
});