document.addEventListener("DOMContentLoaded", () => {
    // Report file upload: the same size limit as the server (MAX_UPLOAD_BYTES in main.py).
    const MAX_UPLOAD_MB = 20;
    const FILE_HINT = `.txt, .pdf or .docx, up to ${MAX_UPLOAD_MB} MB`;

    // ------------------------------------------------------------------
    // Safe display helpers.
    // Anything that comes from a report or from the AI is shown as PLAIN TEXT
    // (textContent), never inserted as page code (innerHTML). A report - or an
    // AI tricked by a report - could otherwise put code into the investigator's
    // browser (this attack is called XSS).
    // ------------------------------------------------------------------
    function textElement(tag, text, className) {
        const el = document.createElement(tag);
        el.textContent = text;
        if (className) el.className = className;
        return el;
    }

    function textList(items) {
        const list = document.createElement("ul");
        items.forEach(item => list.appendChild(textElement("li", String(item))));
        return list;
    }

    function showInBox(boxId, ...children) {
        const box = document.getElementById(boxId);
        box.replaceChildren(...children);
    }

    // ------------------------------------------------------------------
    // Session handling.
    // The login pass is in an httpOnly cookie, which page code can't read (on
    // purpose, so stolen page code can't steal it). So we ASK the server whether
    // we are logged in, and which role we have, instead of guessing.
    // ------------------------------------------------------------------
    let currentRole = null;

    function showLoggedOut(message) {
        currentRole = null;
        showView("login-view");
        resetWorkflow();
        resetNetworkTab();
        // Remove what the previous user loaded, so the next person on this tab cannot read it (e.g. with F12).
        document.querySelector("#audit-table tbody").replaceChildren();
        document.querySelector("#users-table tbody").replaceChildren();
        document.getElementById("login-error").textContent = message || "";
    }

    // Use this for every API call after login: if the server says the session
    // has ended (401), go back to the login screen with the reason.
    async function api(url, options) {
        const res = await fetch(url, options);
        if (res.status === 401) {
            let reason = "Your session has ended. Please log in again.";
            try { reason = (await res.clone().json()).detail || reason; } catch (e) { /* keep default */ }
            showLoggedOut(reason);
        }
        return res;
    }

    async function restoreSession() {
        try {
            const res = await fetch("/api/v1/auth/me");
            if (res.ok) {
                const me = await res.json();
                currentRole = me.role;
                showView("dashboard-view");
                updateNavForRole(currentRole);
                return;
            }
        } catch (e) { /* server unreachable: show the login screen */ }
        showView("login-view");
    }

    restoreSession();

    // Login Form
    document.getElementById("login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const u = document.getElementById("username").value;
        const p = document.getElementById("password").value;
        const err = document.getElementById("login-error");
        err.textContent = "";

        try {
            const res = await fetch("/api/v1/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: u, password: p })
            });

            if (res.ok) {
                const data = await res.json();
                currentRole = data.role;
                showView("dashboard-view");
                updateNavForRole(currentRole);
                showToast("Login successful", "success");
            } else {
                const data = await res.json();
                err.textContent = data.detail || "Login failed";
            }
        } catch (error) {
            err.textContent = "Network error";
        }
    });

    // Logout
    document.getElementById("logout-btn").addEventListener("click", async () => {
        await stopLiveReplay();   // end a running network-sensor live replay first, so it is audited
        try {
            await fetch("/api/v1/auth/logout", { method: "POST" });
        } catch (e) { /* still leave the page logged out */ }
        showLoggedOut();
    });

    // Navigation Tabs
    function showTab(targetId) {
        document.querySelectorAll(".nav-tab").forEach(t =>
            t.classList.toggle("active", t.getAttribute("data-target") === targetId));
        document.querySelectorAll(".tab-content").forEach(c =>
            c.classList.toggle("active", c.id === targetId));
        if (targetId === "audit-tab") loadAuditLogs();
        if (targetId === "admin-tab") { loadConfig(); loadUsers(); }
        if (targetId === "network-tab") loadSensorStatus();
    }

    document.querySelectorAll(".nav-tab").forEach(tab => {
        tab.addEventListener("click", () => showTab(tab.getAttribute("data-target")));
    });

    // Workflow State
    let currentCorrelationId = null;
    let extractedEntities = null;

    // Step 1 (other way in): load the report from a .txt, .pdf or .docx file.
    // The server reads the file and sends back its text, which goes into the paste
    // box. The investigator checks it and clicks "Analyze" as usual.
    const fileInput = document.getElementById("report-file-input");
    const uploadBtn = document.getElementById("upload-file-btn");
    const fileNameLabel = document.getElementById("report-file-name");

    uploadBtn.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", async () => {
        const file = fileInput.files[0];
        fileInput.value = "";                 // so choosing the same file again still works
        if (!file) return;
        if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
            return showToast(`This file is larger than ${MAX_UPLOAD_MB} MB. Split the report, or paste its text instead.`, "error");
        }

        uploadBtn.disabled = true;
        uploadBtn.textContent = "Reading file...";
        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await api("/api/v1/investigation/upload", { method: "POST", body: formData });
            if (res.ok) {
                const data = await res.json();
                // A new report: clear any results that belong to the previous one.
                if (currentCorrelationId) resetWorkflow();
                document.getElementById("report-input").value = data.text;
                fileNameLabel.textContent = `${data.filename} (${data.characters.toLocaleString()} characters)`;
                showToast("Text loaded from the file. Check it, then click Analyze.", "success");
            } else if (res.status !== 401) {  // 401 is already handled by api()
                const err = await res.json().catch(() => ({}));
                showToast(err.detail || "Could not read this file", "error");
            }
        } catch (error) {
            showToast("Network error while uploading the file", "error");
        } finally {
            uploadBtn.disabled = false;
            uploadBtn.textContent = "Upload file";
        }
    });

    // Step 1: Analyze & Extract
    document.getElementById("analyze-btn").addEventListener("click", async () => {
        const text = document.getElementById("report-input").value;
        if (!text.trim()) return showToast("Report text cannot be empty", "error");

        const btn = document.getElementById("analyze-btn");
        btn.textContent = "Processing... (AI is analyzing, hang tight!)";
        btn.disabled = true;

        try {
            // First analyze to get correlation ID
            let res = await api("/api/v1/investigation/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ report_text: text })
            });
            if (!res.ok) {
                // 401 is already handled by api(); show any other error and stop here.
                if (res.status !== 401) {
                    const err = await res.json().catch(() => ({}));
                    showToast(err.detail || "Could not start the analysis", "error");
                }
                return;
            }
            let data = await res.json();
            currentCorrelationId = data.correlation_id;

            // Then extract entities
            res = await api("/api/v1/investigation/entities", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ report_text: text, correlation_id: currentCorrelationId })
            });

            if (res.ok) {
                const entitiesData = await res.json();
                const iocs = entitiesData.iocs || [];
                const actors = entitiesData.threat_actors || [];
                const malware = entitiesData.malware_families || [];
                extractedEntities = [...iocs, ...actors, ...malware];
                
                const title = textElement("strong", "Extracted IOCs:");
                
                const displayElements = [title];
                if (entitiesData.iocs.length === 0) {
                    displayElements.push(textElement("p", "No indicators (CVEs, IPs, domains, hashes) found in this report.", "placeholder-text"));
                } else {
                    displayElements.push(textList(entitiesData.iocs));
                }

                if (entitiesData.threat_actors && entitiesData.threat_actors.length > 0) {
                    displayElements.push(textElement("strong", "Threat Actors:"));
                    displayElements.push(textList(entitiesData.threat_actors));
                }
                
                if (entitiesData.malware_families && entitiesData.malware_families.length > 0) {
                    displayElements.push(textElement("strong", "Malware Families:"));
                    displayElements.push(textList(entitiesData.malware_families));
                }

                showInBox("entities-display", ...displayElements);
                document.getElementById("step-2").classList.remove("disabled");
                document.getElementById("threat-match-btn").disabled = false;
                showToast("Extraction complete", "success");
            } else {
                const err = await res.json();
                showToast(err.detail || "Extraction failed", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.textContent = "Analyze & Extract Entities";
            btn.disabled = false;
        }
    });

    // Step 2: Threat Matching
    document.getElementById("threat-match-btn").addEventListener("click", async () => {
        const btn = document.getElementById("threat-match-btn");
        btn.textContent = "Matching... (AI is querying DB, hang tight!)";
        btn.disabled = true;

        try {
            const res = await api("/api/v1/investigation/threats", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    entities: extractedEntities, 
                    context: document.getElementById("report-input").value,
                    correlation_id: currentCorrelationId 
                })
            });

            if (res.ok) {
                const data = await res.json();
                // Built with textContent (not innerHTML) so text from the server is
                // always shown as plain text and can never run as code in the page.
                const box = document.getElementById("threats-display");
                box.innerHTML = "";
                const title = document.createElement("strong");
                title.textContent = "Threat Matches:";
                box.appendChild(title);

                if (data.status === "unavailable" || data.matches.length === 0) {
                    const note = document.createElement("p");
                    note.className = "placeholder-text";
                    note.textContent = data.message || "No matches found.";
                    box.appendChild(note);
                } else {
                    const list = document.createElement("ul");
                    data.matches.forEach((m, index) => {
                        const item = document.createElement("li");
                        const tactics = (m.mitre_tactics || []).join(", ");
                        item.textContent = `${m.threat} (Confidence: ${m.confidence})` + (tactics ? ` - ${tactics}` : "");

                        // The AI's explanation of the match (the server sends it as "message").
                        if (index === 0 && data.message) {
                            item.appendChild(textElement("p", data.message, "match-explanation"));
                        }

                        // Patch details from Team 3: the update that fixes it, the affected
                        // versions, and what to do until the update can be installed.
                        const patch = m.patch_details || {};
                        const patchRows = [
                            ["Fixed in", patch.fixed_versions],
                            ["Affected versions", patch.affected_versions],
                            ["Workarounds", patch.remediation_workarounds],
                        ]
                            .map(([label, values]) => [label, [].concat(values || []).filter(Boolean)])
                            .filter(([, values]) => values.length > 0);
                        if (patchRows.length > 0) {
                            const block = document.createElement("div");
                            block.className = "patch-details";
                            block.appendChild(textElement("strong", `Patch: ${patch.patch_status || "Unknown"}`));
                            patchRows.forEach(([label, values]) => {
                                block.appendChild(textElement("div", `${label}: ${values.join(", ")}`));
                            });
                            item.appendChild(block);
                        }
                        
                        if (m.citations && m.citations.length > 0) {
                            const citList = document.createElement("ul");
                            citList.style.marginTop = "0.5rem";
                            citList.style.marginBottom = "1rem";
                            m.citations.forEach(c => {
                                const citItem = document.createElement("li");
                                citItem.style.color = "var(--accent)";
                                citItem.style.marginBottom = "0.5rem";
                                citItem.style.lineHeight = "1.5";

                                const badge = document.createElement("span");
                                badge.className = "source-badge";
                                badge.textContent = `Source: ${c.document_id}`;

                                const snippet = document.createTextNode(` "${c.key_excerpt}"`);

                                citItem.appendChild(badge);
                                citItem.appendChild(snippet);
                                citList.appendChild(citItem);
                            });
                            item.appendChild(citList);
                        }

                        list.appendChild(item);
                    });
                    box.appendChild(list);
                }
                document.getElementById("summarize-btn").disabled = false;
                showToast("Threat matching complete", "success");
            } else {
                showToast("Threat matching failed", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.textContent = "Run Threat Matching";
        }
    });

    // Step 2b: Summarize
    document.getElementById("summarize-btn").addEventListener("click", async () => {
        const btn = document.getElementById("summarize-btn");
        btn.textContent = "Synthesizing... (AI is summarizing, hang tight!)";
        btn.disabled = true;

        const evidence = document.getElementById("report-input").value + "\n" + document.getElementById("threats-display").innerText;

        try {
            const res = await api("/api/v1/llm/summarize", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ evidence: evidence, correlation_id: currentCorrelationId })
            });

            if (res.ok) {
                const data = await res.json();
                // The AI's answer is shown as plain text; line breaks are kept by CSS.
                showInBox("summary-display",
                    textElement("strong", "Summary:"),
                    textElement("p", data.summary, "ai-text"),
                    textElement("strong", "Key Points:"),
                    textList(data.key_points || []));
                document.getElementById("step-3").classList.remove("disabled");
                showToast("Synthesis complete", "success");
            } else {
                const err = await res.json();
                const message = err.detail || "Synthesis failed";
                // textContent (not innerHTML) so the error text is shown as plain text
                const box = document.getElementById("summary-display");
                box.innerHTML = "";
                const title = document.createElement("strong");
                title.textContent = "Summary could not be generated:";
                const reason = document.createElement("p");
                reason.textContent = message;
                box.append(title, reason);
                document.getElementById("step-3").classList.remove("disabled");
                showToast(message, "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.textContent = "Synthesize Summary";
            btn.disabled = false;
        }
    });

    // Step 3: Decision
    document.getElementById("submit-decision-btn").addEventListener("click", async () => {
        const decision = document.getElementById("decision-select").value;
        const notes = document.getElementById("decision-notes").value;
        if (!decision) return showToast("Please choose a decision first.", "error");
        const btn = document.getElementById("submit-decision-btn");
        
        btn.disabled = true;
        try {
            const res = await api("/api/v1/investigation/decision", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ decision, notes, correlation_id: currentCorrelationId })
            });
            if (res.ok) {
                showToast("Decision recorded successfully!", "success");
                setTimeout(resetWorkflow, 2000);
            } else if (res.status !== 401) {
                const err = await res.json().catch(() => ({}));
                showToast(err.detail || "Failed to record decision", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.disabled = false;
        }
    });

    // Audit Logs
    document.getElementById("refresh-audit-btn").addEventListener("click", loadAuditLogs);
    async function loadAuditLogs() {
        try {
            const res = await api("/api/v1/admin/audit-logs");
            if (res.ok) {
                const logs = await res.json();
                const tbody = document.querySelector("#audit-table tbody");
                tbody.innerHTML = "";
                // Every cell is filled with textContent (plain text), never innerHTML:
                // entries can contain text typed by anyone, e.g. a made-up username
                // from a failed login, and it must never run as code in this page.
                const cell = (text) => {
                    const td = document.createElement("td");
                    td.textContent = text;
                    return td;
                };
                logs.forEach(log => {
                    let details = {};
                    try { details = JSON.parse(log.details); } catch (e) { /* show the rest anyway */ }

                    // Stored in UTC; shown in this computer's local time, with its time zone.
                    const when = new Date(log.timestamp).toLocaleString(undefined, { timeZoneName: "short" });
                    let who = log.username || log.user;
                    if (details.attempted_username) who += ` (tried: ${details.attempted_username})`;

                    const tr = document.createElement("tr");
                    tr.appendChild(cell(when));
                    tr.appendChild(cell(who));
                    const roleCell = document.createElement("td");
                    const badge = document.createElement("span");
                    badge.className = "badge";
                    badge.textContent = log.role;
                    roleCell.appendChild(badge);
                    tr.appendChild(roleCell);
                    tr.appendChild(cell(log.action));
                    tr.appendChild(cell(details.llm_backend_used || "-"));
                    tr.appendChild(cell(details.outcome || "-"));

                    const viewCell = document.createElement("td");
                    const viewBtn = document.createElement("button");
                    viewBtn.className = "btn outline-btn small-btn";
                    viewBtn.textContent = "View";
                    viewBtn.addEventListener("click", () => {
                        let msg = "";
                        for (const [key, value] of Object.entries(details)) {
                            msg += `${key.replace(/_/g, ' ').toUpperCase()}:\n${value}\n\n`;
                        }
                        alert(msg.trim());
                    });
                    viewCell.appendChild(viewBtn);
                    tr.appendChild(viewCell);

                    tbody.appendChild(tr);
                });
            }
        } catch (e) {
            showToast("Failed to load audit logs", "error");
        }
    }

    // Admin Config
    async function loadConfig() {
        try {
            const res = await api("/api/v1/admin/config");
            if (res.ok) {
                const data = await res.json();
                document.getElementById("llm-backend-select").value = data.llm_backend;
            }
        } catch (e) {
            showToast("Failed to load config", "error");
        }
    }

    document.getElementById("save-config-btn").addEventListener("click", async () => {
        const backend = document.getElementById("llm-backend-select").value;
        try {
            const res = await api("/api/v1/admin/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ llm_backend: backend })
            });
            if (res.ok) showToast("Configuration saved", "success");
        } catch (e) {
            showToast("Failed to save config", "error");
        }
    });

    async function loadUsers() {
        try {
            const res = await api("/api/v1/admin/users");
            if (res.ok) {
                const data = await res.json();
                const tbody = document.querySelector("#users-table tbody");
                tbody.innerHTML = "";
                data.forEach(u => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${u.username}</td>
                        <td>${u.role}</td>
                        <td>
                            <select id="ds-${u.id}" class="dataset-dropdown">
                                <option value="ALL" ${u.allowed_datasets === 'ALL' ? 'selected' : ''}>ALL (Full Access)</option>
                                <option value="INTERNAL" ${u.allowed_datasets === 'INTERNAL' ? 'selected' : ''}>INTERNAL Only</option>
                                <option value="CISA_KEV" ${u.allowed_datasets === 'CISA_KEV' ? 'selected' : ''}>CISA KEV</option>
                                <option value="NVD" ${u.allowed_datasets === 'NVD' ? 'selected' : ''}>NVD</option>
                                <option value="MITRE_ATTACK" ${u.allowed_datasets === 'MITRE_ATTACK' ? 'selected' : ''}>MITRE ATT&CK</option>
                            </select>
                        </td>
                        <td>
                            <button class="btn secondary-btn small-btn save-user-btn" data-user-id="${u.id}">Save</button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
                
                document.querySelectorAll(".save-user-btn").forEach(btn => {
                    btn.addEventListener("click", async (e) => {
                        const userId = e.target.getAttribute("data-user-id");
                        const datasets = document.getElementById(`ds-${userId}`).value;
                        try {
                            const res = await api(`/api/v1/admin/users/${userId}/permissions`, {
                                method: "PUT",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ allowed_datasets: datasets })
                            });
                            if (res.ok) showToast("Permissions updated", "success");
                            else showToast("Failed to update", "error");
                        } catch(err) {
                            showToast("Failed to update", "error");
                        }
                    });
                });
            }
        } catch(e) {
            showToast("Failed to load users", "error");
        }
    }

    document.getElementById("refresh-users-btn").addEventListener("click", loadUsers);

    // ------------------------------------------------------------------
    // Network Sensor tab (Task 5.0).
    // A scan result contains text from the uploaded file (e.g. service names)
    // and from the sensor, so it is shown with textElement (plain text) only,
    // never innerHTML: a crafted file must not be able to put code in the page.
    // ------------------------------------------------------------------
    const MAX_SCAN_MB = 5;     // same limit as MAX_NETWORK_FILE_BYTES in main.py
    const SCAN_HINT = `.csv or .txt (NSL-KDD or CIC-IDS2017 format), up to ${MAX_SCAN_MB} MB`;
    const scanInput = document.getElementById("scan-file-input");
    const scanBtn = document.getElementById("scan-file-btn");
    let lastScanAlerts = [];

    const pct = (x) => `${(100 * x).toFixed(1)}%`;
    const localTime = (iso) => iso ? new Date(iso).toLocaleString(undefined, { timeZoneName: "short" }) : "unknown";

    async function loadSensorStatus() {
        const box = document.getElementById("sensor-status");
        try {
            const res = await api("/api/v1/network/status");
            if (!res.ok) {
                if (res.status !== 401) {
                    box.className = "sensor-status not-ready";
                    showInBox("sensor-status", textElement("p", "Could not check the sensor."));
                }
                return;
            }
            const s = await res.json();
            // One sensor per dataset format (NSL-KDD, CIC-IDS2017); older servers send only one.
            const sensors = s.datasets || [{ ...s, dataset: "nsl_kdd", title: "NSL-KDD" }];
            if (!sensors.some((d) => d.ready)) {
                box.className = "sensor-status not-ready";
                showInBox("sensor-status", textElement("strong", "Sensor not ready"),
                    ...sensors.map((d) => textElement("p", d.message || "")));
                scanBtn.disabled = true;
                return;
            }
            scanBtn.disabled = false;
            box.className = "sensor-status ready";
            const lines = [textElement("strong", "Sensor ready")];
            for (const d of sensors) {
                if (!d.ready) {
                    lines.push(textElement("p", d.message || `${d.title}: not trained yet.`, "muted-text"));
                    continue;
                }
                let text = `${d.title} files: trained ${localTime(d.trained_at)} on ` +
                    `${Number(d.training_connections).toLocaleString()} connections.`;
                const ev = d.evaluation;
                if (ev) {
                    text += ` Last evaluation (${ev.dataset}): precision ${pct(ev.precision)} ` +
                        `(target ${pct(ev.target_precision)}, ${ev.passed ? "passed" : "NOT met"}), ` +
                        `attacks caught ${pct(ev.recall)}, false alarms on ${pct(ev.false_alarm_rate)} of normal traffic.`;
                    lines.push(textElement("p", text));
                } else {
                    const option = d.dataset === "nsl_kdd" ? "" : ` --dataset ${d.dataset}`;
                    lines.push(textElement("p", text));
                    lines.push(textElement("p", "No evaluation report yet. On the server, run: " +
                        `python -m network_sensor.evaluate${option}`, "muted-text"));
                }
            }
            showInBox("sensor-status", ...lines);
        } catch (e) {
            showInBox("sensor-status", textElement("p", "Network error while checking the sensor."));
        }
    }

    scanBtn.addEventListener("click", () => scanInput.click());

    scanInput.addEventListener("change", async () => {
        const file = scanInput.files[0];
        scanInput.value = "";                 // so choosing the same file again still works
        if (!file) return;
        if (file.size > MAX_SCAN_MB * 1024 * 1024) {
            return showToast(`This file is larger than ${MAX_SCAN_MB} MB. Split it into smaller files.`, "error");
        }

        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning... (can take a few seconds)";
        const formData = new FormData();
        formData.append("file", file);
        try {
            const res = await api("/api/v1/network/scan", { method: "POST", body: formData });
            if (res.ok) {
                const data = await res.json();
                document.getElementById("scan-file-name").textContent = data.filename;
                renderScan(data);
                showToast(`Scan complete: ${data.alerts_total.toLocaleString()} alert(s)`, "success");
            } else if (res.status !== 401) {  // 401 is already handled by api()
                const err = await res.json().catch(() => ({}));
                showToast(err.detail || "The file could not be scanned", "error");
            }
        } catch (error) {
            showToast("Network error while scanning the file", "error");
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = "Choose file and scan";
        }
    });

    function statTile(value, label) {
        const tile = document.createElement("div");
        tile.className = "stat";
        tile.append(textElement("div", value, "stat-value"), textElement("div", label, "stat-label"));
        return tile;
    }

    function renderScan(data) {
        const tiles = document.createElement("div");
        tiles.className = "stat-row";
        tiles.append(
            statTile(data.connections.toLocaleString(), "Connections checked"),
            statTile(data.alerts_total.toLocaleString(), "Alerts"),
            statTile(data.possible_new_attacks.toLocaleString(), "Possible new attacks"));
        const parts = [tiles];
        if (data.dataset_title) {
            parts.push(textElement("p", `Checked by the sensor trained on ${data.dataset_title}.`, "muted-text"));
        }
        if (data.label_check) {
            const c = data.label_check;
            parts.push(textElement("p",
                `Compared with the labels in this file: precision ${pct(c.precision)}, attacks caught ${pct(c.recall)}, ` +
                `${c.false_positives.toLocaleString()} false alarm(s). The labels were not used to decide.`, "label-check"));
        }
        if (data.alerts_shown < data.alerts_total) {
            parts.push(textElement("p", `Showing ${data.alerts_shown.toLocaleString()} of ` +
                `${data.alerts_total.toLocaleString()} alerts: the ${data.max_alerts_per_kind} most serious ` +
                `known-pattern alerts and the ${data.max_alerts_per_kind} most serious possible new attacks.`, "muted-text"));
        }
        if (data.alerts_total === 0) {
            parts.push(textElement("p", "No connection in this file looks like an attack.", "muted-text"));
        }
        showInBox("scan-summary", ...parts);

        lastScanAlerts = data.alerts || [];
        document.getElementById("alert-filter").value = "all";
        document.getElementById("alert-filter-row").hidden = lastScanAlerts.length === 0;
        renderAlerts();
    }

    // "Possible new attack" = raised only by the two anomaly models: it does not
    // match any attack the Random Forest learned, but looks clearly abnormal.
    const isPossibleNewAttack = (alert) => alert.votes.random_forest === 0;

    function renderAlerts() {
        const filter = document.getElementById("alert-filter").value;
        const shown = lastScanAlerts.filter(a =>
            filter === "all" || (filter === "new") === isPossibleNewAttack(a));
        const rows = shown.map(alert => {
            const isNew = isPossibleNewAttack(alert);
            const tr = document.createElement("tr");
            const kindCell = document.createElement("td");
            kindCell.appendChild(textElement("span", isNew ? "Possible new attack" : "Known pattern",
                isNew ? "kind-badge new" : "kind-badge known"));

            const why = document.createElement("td");
            why.appendChild(textElement("div", alert.decision, "alert-decision"));
            if (alert.reasons.length > 0) {
                const list = textList(alert.reasons.map(r => r.text));
                list.className = "reason-list";
                why.appendChild(list);
            } else {
                why.appendChild(textElement("div", "No single measurement is unusual on its own.", "muted-text"));
            }
            if (alert.label_in_file !== undefined) {
                why.appendChild(textElement("div", `Label in file: ${alert.label_in_file}`, "alert-label"));
            }
            tr.append(textElement("td", String(alert.row)), kindCell,
                textElement("td", alert.flagged_by.join(", ")),
                textElement("td", pct(alert.random_forest_score)), why);
            return tr;
        });
        document.querySelector("#alerts-table tbody").replaceChildren(...rows);
        document.getElementById("alerts-table").hidden = rows.length === 0;
    }

    document.getElementById("alert-filter").addEventListener("change", renderAlerts);

    // ------------------------------------------------------------------
    // Live mode: the server replays a file as if its connections were arriving
    // now; this page asks once a second what has arrived and shows new alerts at
    // the top of the feed. Plain text only, like the rest of this tab.
    // ------------------------------------------------------------------
    const LIVE_POLL_MS = 1000;
    const LIVE_FEED_MAX = 200;           // older feed entries are removed from the page
    const liveInput = document.getElementById("live-file-input");
    const liveStartBtn = document.getElementById("live-start-btn");
    const liveStopBtn = document.getElementById("live-stop-btn");
    let liveReplay = null;               // { id, timer } while a replay runs

    function setLiveRunning(running) {
        liveStartBtn.hidden = running;
        liveStopBtn.hidden = !running;
        document.getElementById("live-speed").disabled = running;
    }

    liveStartBtn.addEventListener("click", () => liveInput.click());

    liveInput.addEventListener("change", async () => {
        const file = liveInput.files[0];
        liveInput.value = "";
        if (!file) return;
        if (file.size > MAX_SCAN_MB * 1024 * 1024) {
            return showToast(`This file is larger than ${MAX_SCAN_MB} MB. Split it into smaller files.`, "error");
        }
        const speed = document.getElementById("live-speed").value;
        const formData = new FormData();
        formData.append("file", file);
        liveStartBtn.disabled = true;
        try {
            const res = await api(`/api/v1/network/live/start?speed=${encodeURIComponent(speed)}`,
                { method: "POST", body: formData });
            if (res.ok) {
                const data = await res.json();
                resetLivePanel();
                liveReplay = { id: data.session_id, timer: null };
                setLiveRunning(true);
                document.getElementById("live-progress").hidden = false;
                document.getElementById("live-status").textContent =
                    `Replaying ${data.filename}${data.dataset_title ? ` (${data.dataset_title} format)` : ""}: ` +
                    `${data.total.toLocaleString()} connections at ${Number(data.speed).toLocaleString()} per second...`;
                liveReplay.timer = setTimeout(pollLiveReplay, LIVE_POLL_MS);
            } else if (res.status !== 401) {
                const err = await res.json().catch(() => ({}));
                showToast(err.detail || "The live replay could not start", "error");
            }
        } catch (error) {
            showToast("Network error while starting the live replay", "error");
        } finally {
            liveStartBtn.disabled = false;
        }
    });

    async function pollLiveReplay() {
        if (!liveReplay) return;
        const id = liveReplay.id;
        try {
            const res = await api(`/api/v1/network/live/${encodeURIComponent(id)}/next`, { method: "POST" });
            if (!liveReplay || liveReplay.id !== id) return;      // stopped meanwhile
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                endLiveReplay(res.status === 401 ? "Not running." : (err.detail || "The live replay stopped."));
                return;
            }
            const step = await res.json();
            renderLiveStep(step);
            if (step.done) {
                endLiveReplay(`Finished: ${step.checked.toLocaleString()} connections checked, ` +
                    `${step.totals.alerts.toLocaleString()} alert(s).`);
                return;
            }
        } catch (error) {
            endLiveReplay("Network error - the live replay stopped.");
            return;
        }
        liveReplay.timer = setTimeout(pollLiveReplay, LIVE_POLL_MS);
    }

    function renderLiveStep(step) {
        const progress = document.getElementById("live-progress");
        progress.max = step.total;
        progress.value = step.checked;
        let status = `Checked ${step.checked.toLocaleString()} of ${step.total.toLocaleString()} connections ` +
            `(${step.speed.toLocaleString()} per second). Last second: ${step.batch_size.toLocaleString()} ` +
            `connection(s) checked in ${step.check_ms} ms.`;
        if (step.behind_by > 0) status += ` ${step.behind_by.toLocaleString()} waiting to be checked.`;
        document.getElementById("live-status").textContent = status;

        const t = step.totals;
        const tiles = document.createElement("div");
        tiles.className = "stat-row";
        tiles.append(
            statTile(step.checked.toLocaleString(), "Connections checked"),
            statTile(t.alerts.toLocaleString(), "Alerts"),
            statTile(t.possible_new_attacks.toLocaleString(), "Possible new attacks"),
            statTile(`${t.average_check_ms} ms`, "Check time per second of traffic"));
        if (t.label_check) tiles.append(statTile(pct(t.label_check.precision), "Precision so far (labels)"));
        showInBox("live-stats", tiles);

        const feed = document.getElementById("live-feed");
        const now = new Date().toLocaleTimeString();
        step.alerts.forEach(alert => {
            const isNew = isPossibleNewAttack(alert);
            const item = document.createElement("li");
            const head = document.createElement("div");
            head.className = "live-alert-head";
            head.append(textElement("span", now, "live-time"),
                textElement("span", isNew ? "Possible new attack" : "Known pattern",
                    isNew ? "kind-badge new" : "kind-badge known"),
                textElement("span", `Row ${alert.row}`, "live-row"));
            item.append(head, textElement("div", alert.decision, "alert-decision"),
                textElement("div", alert.reasons.length ? alert.reasons[0].text
                    : "No single measurement is unusual on its own.", "live-reason"));
            if (alert.label_in_file !== undefined) {
                item.appendChild(textElement("div", `Label in file: ${alert.label_in_file}`, "alert-label"));
            }
            feed.prepend(item);
        });
        if (step.alerts_in_step > step.alerts.length) {
            feed.prepend(textElement("li", `...and ${(step.alerts_in_step - step.alerts.length).toLocaleString()} ` +
                "more alert(s) in that second (counted above, not listed).", "muted-text"));
        }
        while (feed.children.length > LIVE_FEED_MAX) feed.lastElementChild.remove();
    }

    function endLiveReplay(message) {
        if (liveReplay && liveReplay.timer) clearTimeout(liveReplay.timer);
        liveReplay = null;
        setLiveRunning(false);
        document.getElementById("live-status").textContent = message;
    }

    // Stop button, and logout: tell the server, so the end of the replay is audited.
    async function stopLiveReplay() {
        if (!liveReplay) return;
        const id = liveReplay.id;
        endLiveReplay("Stopping...");
        try {
            const res = await api(`/api/v1/network/live/${encodeURIComponent(id)}/stop`, { method: "POST" });
            if (res.ok) {
                const s = await res.json();
                document.getElementById("live-status").textContent =
                    `Stopped: ${s.connections_checked.toLocaleString()} of ${s.connections_in_file.toLocaleString()} ` +
                    `connections checked, ${s.alerts.toLocaleString()} alert(s).`;
            } else {
                document.getElementById("live-status").textContent = "Stopped.";
            }
        } catch (error) {
            document.getElementById("live-status").textContent = "Stopped.";
        }
    }

    liveStopBtn.addEventListener("click", stopLiveReplay);

    function resetLivePanel() {
        document.getElementById("live-feed").replaceChildren();
        document.getElementById("live-stats").replaceChildren();
        const progress = document.getElementById("live-progress");
        progress.value = 0;
        progress.hidden = true;
        document.getElementById("live-status").textContent = "Not running.";
    }

    function resetNetworkTab() {
        if (liveReplay) endLiveReplay("Not running.");
        resetLivePanel();
        lastScanAlerts = [];
        document.getElementById("scan-file-name").textContent = SCAN_HINT;
        showInBox("scan-summary", textElement("p", "No file scanned yet.", "placeholder-text"));
        document.getElementById("alert-filter-row").hidden = true;
        document.querySelector("#alerts-table tbody").replaceChildren();
        document.getElementById("alerts-table").hidden = true;
        document.getElementById("sensor-status").className = "sensor-status";
        showInBox("sensor-status", textElement("p", "Checking the sensor...", "placeholder-text"));
    }



    // Helpers
    function showView(viewId) {
        document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
        document.getElementById(viewId).classList.add("active");
    }

    // Show only the tabs this role may use (the server enforces the same rules),
    // and open the first of them.
    function updateNavForRole(role) {
        document.getElementById("user-role-badge").textContent = role;
        let firstAllowed = null;
        document.querySelectorAll(".nav-tab").forEach(tab => {
            const allowed = (tab.getAttribute("data-roles") || "").split(" ").includes(role);
            tab.hidden = !allowed;
            if (allowed && !firstAllowed) firstAllowed = tab.getAttribute("data-target");
        });
        if (firstAllowed) showTab(firstAllowed);
    }

    function resetWorkflow() {
        currentCorrelationId = null;
        extractedEntities = null;
        document.getElementById("report-input").value = "";
        document.getElementById("report-file-name").textContent = FILE_HINT;
        document.getElementById("entities-display").innerHTML = '<p class="placeholder-text">Waiting for extraction...</p>';
        document.getElementById("threats-display").innerHTML = "";
        document.getElementById("summary-display").innerHTML = '<p class="placeholder-text">Waiting for synthesis...</p>';
        document.getElementById("step-2").classList.add("disabled");
        document.getElementById("step-3").classList.add("disabled");
        document.getElementById("threat-match-btn").disabled = true;
        document.getElementById("summarize-btn").disabled = true;
        // A new investigation starts with no decision and empty notes.
        document.getElementById("decision-select").value = "";
        document.getElementById("decision-notes").value = "";
    }

    function showToast(msg, type = "error") {
        const container = document.getElementById("toast-container");
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.textContent = msg;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }
});
