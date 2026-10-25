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
                    const ul = document.createElement("ul");
                    entitiesData.iocs.forEach(ioc => {
                        const li = document.createElement("li");
                        li.textContent = ioc;
                        if (/^CVE-\d{4}-\d{4,7}$/i.test(ioc.trim())) {
                            const btn = document.createElement("button");
                            btn.className = "btn outline-btn small-btn";
                            btn.style.marginLeft = "0.75rem";
                            btn.style.padding = "0.15rem 0.45rem";
                            btn.style.fontSize = "0.75rem";
                            btn.textContent = "Search PoCs ↗";
                            btn.onclick = () => window.triggerPoCSearch(ioc.trim());
                            li.appendChild(btn);
                        }
                        ul.appendChild(li);
                    });
                    displayElements.push(ul);
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
                    data.matches.forEach(m => {
                        const item = document.createElement("li");
                        const tactics = (m.mitre_tactics || []).join(", ");
                        const malware = (m.associated_malware || []).join(", ");
                        let extra = "";
                        if (tactics) extra += ` - Tactics: ${tactics}`;
                        if (malware) extra += ` - Malware: ${malware}`;
                        item.textContent = `${m.threat} (Confidence: ${m.confidence})${extra}`;
                        
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
    
    // ------------------------------------------------------------------
    // Task 4: PoC & Exploit Discovery Logic
    // ------------------------------------------------------------------
    const pocSearchBtn = document.getElementById("poc-search-btn");
    if (pocSearchBtn) {
        pocSearchBtn.addEventListener("click", runPoCSearch);
    }
    const pocSearchForm = document.getElementById("poc-search-form");
    if (pocSearchForm) {
        pocSearchForm.addEventListener("submit", (e) => {
            e.preventDefault();
            runPoCSearch();
        });
    }

    async function runPoCSearch() {
        const cveInput = document.getElementById("poc-cve-input");
        const cveId = (cveInput.value || "").trim().toUpperCase();
        if (!cveId) {
            showToast("Please enter a CVE identifier.", "error");
            return;
        }
        if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) {
            showToast("Invalid CVE format. Expected CVE-YYYY-NNNN.", "error");
            return;
        }

        const sources = [];
        if (document.getElementById("poc-src-github").checked) sources.push("github");
        if (document.getElementById("poc-src-mastodon").checked) sources.push("mastodon");
        if (document.getElementById("poc-src-bluesky").checked) sources.push("bluesky");
        if (document.getElementById("poc-src-x").checked) sources.push("x");

        if (sources.length === 0) {
            showToast("Please select at least one OSINT source.", "error");
            return;
        }

        const minConfidence = parseFloat(document.getElementById("poc-min-confidence").value || "0.0");
        const btn = document.getElementById("poc-search-btn");
        btn.textContent = "Harvesting OSINT PoCs...";
        btn.disabled = true;

        try {
            const res = await api("/api/v1/pocs/find", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    cve_id: cveId,
                    max_results: 20,
                    sources: sources,
                    min_confidence: minConfidence
                })
            });

            if (res.ok) {
                const data = await res.json();
                renderPoCResults(data);
                showToast(`Found ${data.total_found} PoC reference(s)`, "success");
            } else {
                const err = await res.json().catch(() => ({}));
                showToast(err.detail || "PoC harvest failed", "error");
            }
        } catch (e) {
            showToast("Network error during PoC search", "error");
        } finally {
            btn.textContent = "Search OSINT PoCs";
            btn.disabled = false;
        }
    }

    function renderPoCResults(data) {
        // 1. Stats banner
        const stats = document.getElementById("poc-stats-banner");
        stats.style.display = "block";
        stats.textContent = `Target: ${data.cve_id} | Total Candidates: ${data.total_found} | Relevance Yield: ${(data.precision_score * 100).toFixed(1)}% | Latency: ${data.latency_ms} ms | Cache: ${data.cached ? "Hit" : "Miss"}`;

        // 2. Source statuses
        const statusesBox = document.getElementById("poc-source-statuses");
        statusesBox.innerHTML = "";
        (data.source_statuses || []).forEach(st => {
            const card = document.createElement("div");
            card.className = "source-status-card";

            const title = document.createElement("strong");
            title.textContent = st.source.toUpperCase();

            let pillClass = "status-pill-success";
            if (st.status === "partial" || st.status === "rate_limited") pillClass = "status-pill-warn";
            else if (st.status === "error" || st.status === "timeout" || st.status === "access_restricted" || st.status === "not_configured") pillClass = "status-pill-err";

            const badge = document.createElement("span");
            badge.className = pillClass;
            badge.textContent = st.status.replace(/_/g, " ");

            const countP = document.createElement("p");
            countP.style.marginTop = "0.4rem";
            countP.textContent = `Results: ${st.result_count} (Pages: ${st.pages_fetched || 1})`;

            card.append(title, badge, countP);

            if (st.errors && st.errors.length > 0) {
                const errP = document.createElement("p");
                errP.style.color = "var(--error-color)";
                errP.style.fontSize = "0.75rem";
                errP.textContent = st.errors[0];
                card.appendChild(errP);
            } else if (st.warnings && st.warnings.length > 0) {
                const warnP = document.createElement("p");
                warnP.style.color = "#b06000";
                warnP.style.fontSize = "0.75rem";
                warnP.textContent = st.warnings[0];
                card.appendChild(warnP);
            }
            statusesBox.appendChild(card);
        });

        // 3. Results cards
        const resultsBox = document.getElementById("poc-results-container");
        resultsBox.innerHTML = "";

        if (!data.results || data.results.length === 0) {
            resultsBox.innerHTML = '<p class="placeholder-text">No matching PoCs or discussions met the relevance criteria for this query.</p>';
            return;
        }

        data.results.forEach((r, idx) => {
            const card = document.createElement("div");
            card.className = "poc-card";

            const header = document.createElement("div");
            header.className = "poc-header";

            const titleBox = document.createElement("div");
            titleBox.className = "poc-title";
            const link = document.createElement("a");
            link.href = r.url;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = `${idx + 1}. ${r.title || r.url}`;
            titleBox.appendChild(link);

            const badgesBox = document.createElement("div");
            badgesBox.className = "poc-badges";

            const labelBadge = document.createElement("span");
            const lbl = r.confidence_label || r.match_type || "LOW_CONFIDENCE";
            if (lbl === "HIGH_RELEVANCE_POC_CANDIDATE" || lbl === "VERIFIED_CODE") labelBadge.className = "badge-high";
            else if (lbl === "POSSIBLE_POC" || lbl === "LIKELY_POC") labelBadge.className = "badge-possible";
            else if (lbl === "ADVISORY_OR_PATCH") labelBadge.className = "badge-advisory";
            else if (lbl === "SUSPICIOUS") labelBadge.className = "badge-suspicious";
            else labelBadge.className = "badge-discussion";
            labelBadge.textContent = lbl.replace(/_/g, " ");

            const scoreBadge = document.createElement("span");
            scoreBadge.className = "badge";
            scoreBadge.textContent = `Score: ${(r.confidence_score).toFixed(2)}`;

            const srcBadge = document.createElement("span");
            srcBadge.className = "badge";
            srcBadge.textContent = r.source.toUpperCase();

            badgesBox.append(labelBadge, scoreBadge, srcBadge);
            header.append(titleBox, badgesBox);
            card.appendChild(header);

            // Metadata row
            const metaP = document.createElement("p");
            metaP.style.fontSize = "0.85rem";
            metaP.style.color = "var(--text-secondary)";
            metaP.style.marginBottom = "0.5rem";
            const metaParts = [`Author: ${r.author || "unknown"}`];
            if (r.stars !== null && r.stars !== undefined) metaParts.push(`Stars: ${r.stars}`);
            if (r.language) metaParts.push(`Language: ${r.language}`);
            if (r.published_at) metaParts.push(`Published: ${r.published_at.slice(0, 10)}`);
            if (r.is_fork) metaParts.push("Fork: Yes");
            metaP.textContent = metaParts.join(" | ");
            card.appendChild(metaP);

            // Warning flags
            if (r.warning_flags && r.warning_flags.length > 0) {
                const warnDiv = document.createElement("div");
                warnDiv.style.marginBottom = "0.5rem";
                r.warning_flags.forEach(flag => {
                    const pill = document.createElement("span");
                    pill.className = "warning-pill";
                    pill.textContent = `⚠ ${flag.replace(/_/g, " ")}`;
                    warnDiv.appendChild(pill);
                });
                card.appendChild(warnDiv);
            }

            // Evidence and Reasons Accordion/List
            const details = document.createElement("details");
            details.style.fontSize = "0.82rem";
            details.style.marginTop = "0.5rem";
            const summary = document.createElement("summary");
            summary.style.cursor = "pointer";
            summary.style.color = "var(--primary-color)";
            summary.textContent = `View Observable Evidence (${(r.evidence || []).length}) & Score Reasons (${(r.score_reasons || []).length})`;
            details.appendChild(summary);

            const detailsBody = document.createElement("div");
            detailsBody.style.marginTop = "0.5rem";
            detailsBody.style.paddingLeft = "1rem";

            if (r.evidence && r.evidence.length > 0) {
                const evTitle = document.createElement("strong");
                evTitle.textContent = "Observed Evidence:";
                detailsBody.appendChild(evTitle);
                const evList = document.createElement("ul");
                evList.style.marginBottom = "0.5rem";
                r.evidence.forEach(ev => {
                    const li = document.createElement("li");
                    li.textContent = ev;
                    evList.appendChild(li);
                });
                detailsBody.appendChild(evList);
            }

            if (r.score_reasons && r.score_reasons.length > 0) {
                const rTitle = document.createElement("strong");
                rTitle.textContent = "Deterministic Scoring Contributions:";
                detailsBody.appendChild(rTitle);
                const rList = document.createElement("ul");
                rList.style.marginBottom = "0.5rem";
                r.score_reasons.forEach(rs => {
                    const li = document.createElement("li");
                    li.textContent = rs;
                    rList.appendChild(li);
                });
                detailsBody.appendChild(rList);
            }

            if (r.source_references && r.source_references.length > 1) {
                const provTitle = document.createElement("strong");
                provTitle.textContent = "Corroborated by Multiple Sources:";
                detailsBody.appendChild(provTitle);
                const provList = document.createElement("ul");
                r.source_references.forEach(sref => {
                    const li = document.createElement("li");
                    li.textContent = `[${sref.source.toUpperCase()}] ${sref.url} (${sref.author || "unknown"})`;
                    provList.appendChild(li);
                });
                detailsBody.appendChild(provList);
            }

            const disclaimP = document.createElement("p");
            disclaimP.style.fontStyle = "italic";
            disclaimP.style.color = "var(--text-secondary)";
            disclaimP.style.marginTop = "0.4rem";
            disclaimP.textContent = "Classification based on public OSINT metadata and search heuristics. Does not validate execution safety or exploit payload viability.";
            detailsBody.appendChild(disclaimP);

            details.appendChild(detailsBody);
            card.appendChild(details);

            resultsBox.appendChild(card);
        });
    }

    // Export triggerPoCSearch globally so entity clicks can invoke it
    window.triggerPoCSearch = function(cve) {
        showTab("poc-tab");
        const inp = document.getElementById("poc-cve-input");
        if (inp) inp.value = cve;
        runPoCSearch();
    };

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
