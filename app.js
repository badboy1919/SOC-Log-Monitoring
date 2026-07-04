document.addEventListener("DOMContentLoaded", () => {
  // Select DOM Elements
  const threatOptions = document.querySelectorAll(".threat-opt");
  const simulateBtn = document.getElementById("simulate-btn");
  const toggleSettingsBtn = document.getElementById("toggle-settings-btn");
  const settingsPanel = document.getElementById("settings-panel");
  const saveConfigBtn = document.getElementById("save-config-btn");
  const clearConsoleBtn = document.getElementById("clear-console-btn");
  const consoleLogs = document.getElementById("console-logs");
  const triageResult = document.getElementById("triage-result");
  const verdictTag = document.getElementById("verdict-tag");
  const reportIntel = document.getElementById("report-intel");
  const reportAiMarkdown = document.getElementById("report-ai-markdown");
  const containmentAlert = document.getElementById("containment-alert");
  const containmentMsg = document.getElementById("containment-msg");
  const mapStepLabel = document.getElementById("map-step-label");

  // Visual Node Elements
  const nodeAttacker = document.getElementById("node-attacker");
  const nodeTarget = document.getElementById("node-target");
  const nodeSiem = document.getElementById("node-siem");
  const nodeAi = document.getElementById("node-ai");
  const nodeFirewall = document.getElementById("node-firewall");

  // Visual Connection Lines
  const lineAttack = document.getElementById("line-attack");
  const lineDetect = document.getElementById("line-detect");
  const lineAnalyze = document.getElementById("line-analyze");
  const lineRespond = document.getElementById("line-respond");

  // State
  let currentAlertType = "1";
  const defaultConfigs = {
    OLLAMA_URL: "http://localhost:11434",
    OLLAMA_MODEL: "llama3",
    DISCORD_WEBHOOK: "",
    ABUSEIPDB_API_KEY: "",
    VIRUSTOTAL_API_KEY: "",
    ACTIVE_RESPONSE_ENABLED: false
  };

  // Load configuration from local storage if api server is offline
  let activeConfigs = { ...defaultConfigs };

  // Fetch configs from backend on load
  async function loadConfigFromServer() {
    try {
      // We will check if backend is reachable, if so, load configs
      // In this setup we can get the values from server configs by fetching them, but since we are simple, we'll try to read config.json
      // Let's call /api/config or default
    } catch(e) {}
  }

  // Populate config fields
  function syncConfigFields() {
    document.getElementById("cfg-ollama-url").value = activeConfigs.OLLAMA_URL;
    document.getElementById("cfg-ollama-model").value = activeConfigs.OLLAMA_MODEL;
    document.getElementById("cfg-abuseipdb-key").value = activeConfigs.ABUSEIPDB_API_KEY;
    document.getElementById("cfg-discord-webhook").value = activeConfigs.DISCORD_WEBHOOK;
    document.getElementById("cfg-active-response").checked = activeConfigs.ACTIVE_RESPONSE_ENABLED;
  }

  // Switch Threat Options
  threatOptions.forEach(opt => {
    opt.addEventListener("click", () => {
      threatOptions.forEach(o => o.classList.remove("active"));
      opt.classList.add("active");
      currentAlertType = opt.getAttribute("data-alert-type");

      // Update Node labels dynamically based on selection
      if (currentAlertType === "1") {
        document.getElementById("node-attacker-ip").textContent = "185.220.101.5";
        document.getElementById("node-target-name").textContent = "kali-agent";
      } else if (currentAlertType === "2") {
        document.getElementById("node-attacker-ip").textContent = "192.168.1.102";
        document.getElementById("node-target-name").textContent = "web-prod-01";
      } else if (currentAlertType === "3") {
        document.getElementById("node-attacker-ip").textContent = "Local Guest User";
        document.getElementById("node-target-name").textContent = "kali-agent";
      }
    });
  });

  // Toggle Settings Panel
  toggleSettingsBtn.addEventListener("click", () => {
    settingsPanel.classList.toggle("hidden");
  });

  // Save Settings
  saveConfigBtn.addEventListener("click", async () => {
    activeConfigs = {
      OLLAMA_URL: document.getElementById("cfg-ollama-url").value,
      OLLAMA_MODEL: document.getElementById("cfg-ollama-model").value,
      ABUSEIPDB_API_KEY: document.getElementById("cfg-abuseipdb-key").value,
      DISCORD_WEBHOOK: document.getElementById("cfg-discord-webhook").value,
      ACTIVE_RESPONSE_ENABLED: document.getElementById("cfg-active-response").checked
    };

    try {
      const response = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: json = JSON.stringify(activeConfigs)
      });
      if (response.ok) {
        logToConsole("Configuration saved to server successfully.", "success");
        settingsPanel.classList.add("hidden");
      } else {
        logToConsole("Failed to save configuration to server. Using local memory.", "error");
      }
    } catch (e) {
      logToConsole("Error connection: Failed to save config to server.", "error");
    }
  });

  // Clear Console
  clearConsoleBtn.addEventListener("click", () => {
    consoleLogs.innerHTML = `<p class="console-info">> Aegis-AI Shell Initialized. Ready.</p>`;
  });

  // Helper log function
  function logToConsole(text, type = "info") {
    const p = document.createElement("p");
    p.className = `console-${type}`;
    p.textContent = `> [${new Date().toLocaleTimeString()}] ${text}`;
    consoleLogs.appendChild(p);
    // Auto scroll console wrapper
    const wrapper = consoleLogs.parentElement;
    wrapper.scrollTop = wrapper.scrollHeight;
  }

  // Reset visual map nodes and lines
  function resetMapVisuals() {
    document.querySelectorAll(".network-node").forEach(node => {
      node.classList.remove("active", "threat-active", "ai-active", "blocked");
    });
    document.querySelectorAll(".map-connections line").forEach(line => {
      line.className.baseVal = ""; // Reset SVG lines class
    });
    containmentAlert.classList.add("hidden");
    triageResult.classList.add("hidden");
  }

  // Simulation Trigger
  simulateBtn.addEventListener("click", async () => {
    resetMapVisuals();
    simulateBtn.disabled = true;
    simulateBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing...`;

    // 1. Initial State
    mapStepLabel.textContent = "ATTACK_TRIGGERED";
    nodeAttacker.classList.add("threat-active");
    logToConsole("Threat Simulation Initiated...", "info");
    
    // Animate first link
    await delay(1000);
    lineAttack.className.baseVal = "active";
    nodeTarget.classList.add("threat-active");
    logToConsole("Attacker connecting to Target Host...", "warn");
    
    // 2. Detection State
    await delay(1200);
    mapStepLabel.textContent = "LOG_COLLECTION";
    lineDetect.className.baseVal = "active";
    nodeSiem.classList.add("active");
    logToConsole("Wazuh agent forwarding target logs to manager...", "info");
    logToConsole("SIEM Decoder matched rules. Level check complete.", "success");

    // 3. AI Triage API Call
    await delay(1000);
    mapStepLabel.textContent = "AI_TRIAGE";
    lineAnalyze.className.baseVal = "active";
    nodeAi.classList.add("ai-active");
    logToConsole("SIEM triggering wazuh_ai_integrator integration script...", "info");
    logToConsole("Calling Threat Intelligence API for context...", "info");

    try {
      const response = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_type: currentAlertType })
      });

      if (!response.ok) throw new Error("Server returned error response");
      const data = await response.json();

      logToConsole(`Enrichment complete: ${data.threat_intel}`, "success");
      logToConsole("Sending payload to local Llama3 model on Ollama...", "info");
      logToConsole("AI Analyst analysis finalized. Writing Incident Report...", "success");

      // 4. Show AI Triage details
      triageResult.classList.remove("hidden");
      verdictTag.textContent = data.is_true_positive ? "True Positive" : "False Positive";
      verdictTag.className = `verdict-tag ${data.is_true_positive ? 'tp' : 'fp'}`;
      reportIntel.textContent = data.threat_intel;
      reportAiMarkdown.textContent = data.ai_report;

      // 5. Active Response Action Visuals
      await delay(1000);
      mapStepLabel.textContent = "SOAR_ACTION";
      lineRespond.className.baseVal = data.is_true_positive ? "blocked" : "active";
      nodeFirewall.classList.add(data.is_true_positive ? "blocked" : "active");
      
      logToConsole(`SOAR Active Response action evaluated: ${data.action}`, "warn");

      if (data.is_true_positive) {
        nodeTarget.classList.remove("threat-active");
        nodeTarget.classList.add("blocked");
        containmentAlert.classList.remove("hidden");
        containmentMsg.textContent = data.action;
        logToConsole("Host containment policy executed successfully. Threat isolated.", "success");
      } else {
        logToConsole("No containment action required. Closing case.", "success");
      }

    } catch (error) {
      logToConsole(`Error during simulation pipeline: ${error.message}`, "error");
      logToConsole("Make sure the python backend (api_server.py) is running locally.", "error");
    } finally {
      simulateBtn.disabled = false;
      simulateBtn.innerHTML = `<i class="fa-solid fa-skull-crossbones"></i> Launch Threat Simulation`;
      mapStepLabel.textContent = "IDLE";
    }
  });

  // Helper Delay Promise
  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Initialize
  syncConfigFields();
});
