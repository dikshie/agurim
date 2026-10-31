/**
 * Agurim AI NOC Copilot Client
 * Powered by Google ADK (Agent Development Kit) Multi-Agent Architecture
 */

(function () {
    "use strict";

    var copilotState = {
        isOpen: false,
        isProcessing: false,
        dataset: "sample",
        criteria: "byte",
        view: "addr"
    };

    function initCopilot() {
        // Create Copilot Toggle Button in Navbar if not present
        if (!document.getElementById("btnToggleCopilot")) {
            var navPills = document.querySelector(".header .nav-pills");
            if (navPills) {
                var li = document.createElement("li");
                li.innerHTML = '<a href="javascript:void(0)" id="btnToggleCopilot" style="background:#4285F4;color:#fff;border-radius:4px;padding:8px 12px;font-weight:bold;"><span class="glyphicon glyphicon-flash"></span> AI Copilot</a>';
                navPills.insertBefore(li, navPills.firstChild);
            }
        }

        // Inject Sidebar Drawer HTML
        var drawerHtml = [
            '<div id="agurimCopilotDrawer" style="position:fixed;top:0;right:-460px;width:450px;height:100%;background:#ffffff;box-shadow:-3px 0 16px rgba(0,0,0,0.2);z-index:9999;transition:right 0.3s ease;display:flex;flex-direction:column;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;">',
            '  <div style="background:#202124;color:#fff;padding:14px 18px;display:flex;justify-content:space-between;align-items:center;">',
            '    <div>',
            '      <h4 style="margin:0;font-size:16px;font-weight:600;"><span class="glyphicon glyphicon-flash" style="color:#FBBC04;"></span> Agurim AI NOC Copilot</h4>',
            '      <small style="color:#9AA0A6;font-size:11px;">Google ADK Multi-Agent Team (Gemini)</small>',
            '    </div>',
            '    <button id="btnCloseCopilot" type="button" class="btn btn-xs btn-default" style="background:transparent;border:none;color:#fff;font-size:18px;">&times;</button>',
            '  </div>',
            '  <div id="copilotSuggestions" style="padding:10px 14px;background:#f8f9fa;border-bottom:1px solid #e0e0e0;display:flex;gap:6px;flex-wrap:wrap;">',
            '    <button class="btn btn-xs btn-default copilot-chip" data-prompt="Analyze current traffic and heavy hitters">📊 Analyze Traffic</button>',
            '    <button class="btn btn-xs btn-default copilot-chip" data-prompt="Investigate any abnormal bandwidth spikes or bursts">⚡ Spike Check</button>',
            '    <button class="btn btn-xs btn-default copilot-chip" data-prompt="Diagnose potential DDoS or amplification attacks">🛡️ DDoS Diagnosis</button>',
            '    <button class="btn btn-xs btn-default copilot-chip" data-prompt="Generate safety-certified BGP Flowspec and ACL rules">📝 Mitigations</button>',
            '  </div>',
            '  <div id="copilotMessages" style="flex:1;overflow-y:auto;padding:16px;background:#ffffff;display:flex;flex-direction:column;gap:12px;">',
            '    <div style="background:#f1f3f4;border-radius:8px;padding:12px;font-size:13px;line-height:1.5;">',
            '      <strong>👋 Welcome to Agurim AI NOC Copilot!</strong><br>',
            '      I lead a specialized Google ADK multi-agent team (<b>DataEngineer</b>, <b>ParallelAnomalyTeam</b>, and <b>SafetyCritic</b>). Ask me to analyze traffic, diagnose spikes, or generate certified mitigation rules.',
            '    </div>',
            '  </div>',
            '  <div style="padding:12px;border-top:1px solid #e0e0e0;background:#fafafa;">',
            '    <form id="copilotForm" style="display:flex;gap:8px;margin:0;">',
            '      <input id="copilotInput" type="text" class="form-control input-sm" placeholder="Ask AI NOC Copilot..." style="flex:1;" />',
            '      <button type="submit" id="btnSendCopilot" class="btn btn-sm btn-primary" style="background:#4285F4;border-color:#4285F4;">Send</button>',
            '    </form>',
            '  </div>',
            '</div>'
        ].join("\n");

        var container = document.createElement("div");
        container.innerHTML = drawerHtml;
        document.body.appendChild(container.firstChild);

        // Bind events
        document.getElementById("btnToggleCopilot").addEventListener("click", toggleDrawer);
        document.getElementById("btnCloseCopilot").addEventListener("click", toggleDrawer);

        var chips = document.querySelectorAll(".copilot-chip");
        chips.forEach(function (chip) {
            chip.addEventListener("click", function () {
                var prompt = this.getAttribute("data-prompt");
                sendCopilotMessage(prompt);
            });
        });

        document.getElementById("copilotForm").addEventListener("submit", function (e) {
            e.preventDefault();
            var input = document.getElementById("copilotInput");
            var text = input.value.trim();
            if (text) {
                input.value = "";
                sendCopilotMessage(text);
            }
        });
    }

    function toggleDrawer() {
        var drawer = document.getElementById("agurimCopilotDrawer");
        if (!drawer) return;
        copilotState.isOpen = !copilotState.isOpen;
        drawer.style.right = copilotState.isOpen ? "0px" : "-460px";
    }

    function formatMarkdown(text) {
        if (!text) return "";
        // Basic Markdown formatter for chat UI
        var html = text
            .replace(/^### (.*$)/gim, '<h5 style="margin:8px 0 4px;font-weight:700;color:#202124;">$1</h5>')
            .replace(/^## (.*$)/gim, '<h4 style="margin:10px 0 6px;font-weight:700;color:#202124;">$1</h4>')
            .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
            .replace(/\*(.*?)\*/g, '<i>$1</i>')
            .replace(/```(text|bash)?\n([\s\S]*?)```/g, '<pre style="background:#282c34;color:#abb2bf;padding:8px;border-radius:4px;font-size:11px;overflow-x:auto;">$2</pre>')
            .replace(/`([^`]+)`/g, '<code style="background:#e8eaed;color:#202124;padding:2px 4px;border-radius:3px;font-size:12px;">$1</code>')
            .replace(/\n/g, '<br/>');
        return html;
    }

    function appendMessage(sender, text, traces, isUser) {
        var box = document.getElementById("copilotMessages");
        if (!box) return;

        var msgDiv = document.createElement("div");
        msgDiv.style.borderRadius = "8px";
        msgDiv.style.padding = "10px 14px";
        msgDiv.style.fontSize = "13px";
        msgDiv.style.lineHeight = "1.5";
        msgDiv.style.maxWidth = "92%";

        if (isUser) {
            msgDiv.style.background = "#E8F0FE";
            msgDiv.style.color = "#1967D2";
            msgDiv.style.alignSelf = "flex-end";
            msgDiv.innerHTML = "<b>You:</b> " + text;
        } else {
            msgDiv.style.background = "#F8F9FA";
            msgDiv.style.color = "#202124";
            msgDiv.style.border = "1px solid #E0E0E0";
            msgDiv.style.alignSelf = "flex-start";

            var traceHtml = "";
            if (traces && traces.length > 0) {
                traceHtml += '<div style="margin-bottom:8px;padding-bottom:6px;border-bottom:1px dashed #dcdcdc;display:flex;flex-direction:column;gap:4px;">';
                traces.forEach(function (t) {
                    var badgeColor = t.agent.indexOf("Safety") !== -1 ? "#34A853" : (t.agent.indexOf("Anomaly") !== -1 || t.agent.indexOf("Volume") !== -1 ? "#EA4335" : "#4285F4");
                    traceHtml += '<div style="font-size:11px;color:#5f6368;"><span style="background:' + badgeColor + ';color:#fff;padding:1px 5px;border-radius:3px;font-weight:bold;margin-right:4px;">' + t.agent + '</span> ' + t.detail + '</div>';
                });
                traceHtml += '</div>';
            }

            msgDiv.innerHTML = traceHtml + formatMarkdown(text);
        }

        box.appendChild(msgDiv);
        box.scrollTop = box.scrollHeight;
    }

    function sendCopilotMessage(prompt) {
        if (copilotState.isProcessing) return;
        copilotState.isProcessing = true;

        appendMessage("You", prompt, null, true);

        // Loading indicator
        var box = document.getElementById("copilotMessages");
        var loader = document.createElement("div");
        loader.id = "copilotLoader";
        loader.style.fontSize = "12px";
        loader.style.color = "#70757a";
        loader.style.fontStyle = "italic";
        loader.innerText = "🤖 Multi-Agent NOC Team is analyzing Agurim records...";
        box.appendChild(loader);
        box.scrollTop = box.scrollHeight;

        // Context extraction from current page
        var currentDs = document.getElementById("hiddenDataset") ? document.getElementById("hiddenDataset").value : "sample";
        var currentView = document.getElementById("hiddenView") ? document.getElementById("hiddenView").value : "addr";

        var payload = {
            message: prompt,
            context: {
                dataset: currentDs || "sample",
                view: currentView || "addr"
            }
        };

        fetch("/api/agent/chat", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        })
            .then(function (res) {
                return res.json();
            })
            .then(function (data) {
                if (loader.parentNode) loader.parentNode.removeChild(loader);
                copilotState.isProcessing = false;

                if (data.status === "success") {
                    appendMessage("NOC", data.response, data.traces, false);

                    // Execute UI Action if returned
                    if (data.ui_action && typeof window.myAgurim !== "undefined") {
                        handleUiAction(data.ui_action);
                    }
                } else {
                    appendMessage("NOC", "⚠️ Error executing agent analysis: " + (data.error || data.message || "Unknown error"), null, false);
                }
            })
            .catch(function (err) {
                if (loader.parentNode) loader.parentNode.removeChild(loader);
                copilotState.isProcessing = false;
                appendMessage("NOC", "⚠️ Failed to connect to /api/agent/chat: " + err, null, false);
            });
    }

    function handleUiAction(action) {
        console.log("[Copilot] Applying UI action:", action);
        if (action.filter && typeof window.myAgurim.filterFlow === "function") {
            window.myAgurim.filterFlow(action.filter);
        }
    }

    // Auto-initialize when DOM is ready
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initCopilot);
    } else {
        initCopilot();
    }
})();
