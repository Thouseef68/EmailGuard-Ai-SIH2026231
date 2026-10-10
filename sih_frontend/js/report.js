// js/report.js
// ── Full report renderer — all sections ───────────────────────────────────

const ReportRenderer = {

    report: null,
    role:   null,

    render(report) {
        this.report = report;
        this.role   = Utils.getUserRole();
        const root  = document.getElementById("report-content");
        root.innerHTML = `
            ${this.renderVerdictHero()}
            ${this.renderLLMAnalyst()}
            ${this.renderEmailMeta()}
            ${this.renderFlags()}
            ${this.renderAIScores()}
            ${this.renderSHAP()}
            ${this.renderIntent()}
            ${this.renderForensics()}
            ${this.renderGeoIP()}
            ${this.renderVision()}
            ${this.renderAttachments()}
            ${this.renderSMTPChain()}
            ${this.renderBlockchain()}
            ${this.renderDownloadBar()}
        `;
        // Post-render
        this.initSHAPChart();
        this.initGeoIPMap();
        this.pollBlockchain();
    },

    // ── helpers ───────────────────────────────────────────────────────────
    // Everything that originates in an email or in LLM output is untrusted and
    // is escaped before it is placed in innerHTML.
    _esc(v) {
        return String(v ?? "").replace(/[&<>"']/g, c => (
            { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
        ));
    },

    // ── 1. VERDICT HERO (final verdict = AI analyst, validated) ───────────
    renderVerdictHero() {
        const report = this.report || {};
        const llm    = report.llm_analyst || {};

        let v = report.final_verdict || llm.verdict || "HUMAN_REVIEW";
        if (v === "UNKNOWN") v = "HUMAN_REVIEW";

        const conf     = report.final_confidence ?? llm.confidence;
        const fallback = llm.status === "fallback";
        const reason   = report.decision_reason || "";
        const subject  = report.parsed?.subject || "Unknown Subject";
        const source   = report.source || "";

        const icon   = Utils.verdictIcon(v);
        const bgCls  = Utils.verdictBg(v);
        const txtCls = Utils.verdictColor(v);

        const label = { PHISHING: "PHISHING", LEGITIMATE: "LEGITIMATE", HUMAN_REVIEW: "HUMAN REVIEW" }[v] || v;

        return `
        <div class="${bgCls} rounded-2xl p-8 mb-6 text-center">
            <div class="text-6xl mb-4">${icon}</div>
            <p class="text-slate-400 text-sm uppercase tracking-wider">Final Verdict</p>
            <h1 class="${txtCls} text-5xl font-extrabold mb-2">${this._esc(label)}</h1>

            <div class="mt-5 space-y-2">
                ${conf !== undefined && conf !== null ? `
                <p class="text-slate-300 text-lg">
                    Analyst confidence: <span class="font-bold">${this._esc(conf)}%</span>
                </p>` : ""}
                <p class="text-slate-400 text-sm">
                    Decided by the EmailGuard AI analyst${llm.model ? ` · ${this._esc(llm.model)}` : ""}
                </p>
                ${fallback ? `
                <p class="text-yellow-300 text-sm font-medium">
                    ⚠ The AI analyst was unavailable, so this email was sent to human review.
                </p>` : ""}
                ${reason ? `<p class="text-slate-300 text-sm mt-2 max-w-2xl mx-auto">${this._esc(reason)}</p>` : ""}
            </div>

            <p class="text-slate-400 text-sm mt-5 truncate max-w-xl mx-auto" title="${this._esc(subject)}">
                📧 ${this._esc(subject)}
            </p>
            ${source ? `<p class="text-slate-600 text-xs mt-1">${this._esc(source)}</p>` : ""}
        </div>`;
    },

    // ── 1b. AI ANALYST REVIEW ─────────────────────────────────────────────
    renderLLMAnalyst() {
        const llm = this.report?.llm_analyst;
        if (!llm) return "";

        const sevCls = {
            HIGH:   "border-red-500/40 bg-red-500/10 text-red-300",
            MEDIUM: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
            LOW:    "border-slate-600 bg-slate-800/60 text-slate-300",
            INFO:   "border-slate-700 bg-slate-800/40 text-slate-400",
        };
        const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

        const reasons = (llm.reasons || []).map((r, i) => `
            <li class="flex gap-3 text-sm text-slate-200">
                <span class="text-indigo-400 font-bold flex-shrink-0">${i + 1}.</span>
                <span>${this._esc(r)}</span>
            </li>`).join("");

        const findings = [...(llm.forensic_findings || [])]
            .sort((a, b) => (order[String(a.severity).toUpperCase()] ?? 9) - (order[String(b.severity).toUpperCase()] ?? 9))
            .map(f => {
                const sev = String(f.severity || "INFO").toUpperCase();
                return `
                <li class="flex items-start gap-3 px-4 py-3 rounded-lg border ${sevCls[sev] || sevCls.INFO} text-sm">
                    <span class="font-mono text-xs flex-shrink-0 mt-0.5">${this._esc(f.id)}</span>
                    <span class="text-xs font-bold flex-shrink-0 mt-0.5 w-16">${this._esc(sev)}</span>
                    <span>${this._esc(f.text)}</span>
                </li>`;
            }).join("");

        const highs = (llm.high_findings || []).map(h => `
            <li class="flex items-start gap-3 text-sm">
                <span class="font-mono text-xs text-slate-400 flex-shrink-0 mt-0.5">${this._esc(h.id)}</span>
                <span class="text-xs font-bold flex-shrink-0 mt-0.5 w-20 ${h.stance === "confirmed" ? "text-red-400" : "text-green-400"}">${this._esc(String(h.stance || "").toUpperCase())}</span>
                <span class="text-slate-300">${this._esc(h.why || "")}</span>
            </li>`).join("");

        const notes = (llm.validation_notes || []).map(n => `
            <li class="text-xs text-slate-400">• ${this._esc(n)}</li>`).join("");

        const changed = llm.llm_verdict_raw && llm.verdict && llm.llm_verdict_raw !== llm.verdict;

        return `
        <div class="bg-slate-900 border border-indigo-500/30 rounded-2xl p-6 mb-6">
            <div class="flex flex-wrap items-center justify-between gap-2 mb-5">
                <h2 class="text-white font-bold text-lg">🧠 AI Analyst Review</h2>
                <div class="flex flex-wrap gap-2 text-xs">
                    ${llm.model ? `<span class="px-3 py-1 bg-slate-800 border border-slate-700 rounded-full text-slate-300">${this._esc(llm.model)}</span>` : ""}
                    ${llm.latency_ms ? `<span class="px-3 py-1 bg-slate-800 border border-slate-700 rounded-full text-slate-400">${this._esc(llm.latency_ms)} ms</span>` : ""}
                    ${llm.re_asked ? `<span class="px-3 py-1 bg-yellow-500/10 border border-yellow-500/40 rounded-full text-yellow-300">Asked twice</span>` : ""}
                </div>
            </div>

            ${llm.status === "fallback" ? `
            <div class="mb-5 p-4 rounded-xl border border-yellow-500/40 bg-yellow-500/10 text-yellow-200 text-sm">
                The AI analyst could not complete this review${llm.error ? ` (${this._esc(llm.error)})` : ""}. The email was routed to human review instead of being guessed.
            </div>` : ""}

            ${changed ? `
            <div class="mb-5 p-4 rounded-xl border border-yellow-500/40 bg-yellow-500/10 text-yellow-200 text-sm">
                The analyst first answered <b>${this._esc(llm.llm_verdict_raw)}</b>; after validation against the verified facts the final verdict is <b>${this._esc(llm.verdict)}</b>.
            </div>` : ""}

            ${reasons ? `
            <p class="text-slate-400 text-xs uppercase tracking-wide mb-3 font-medium">Why</p>
            <ul class="space-y-2 mb-6">${reasons}</ul>` : ""}

            ${findings ? `
            <p class="text-slate-400 text-xs uppercase tracking-wide mb-3 font-medium">Verified findings (computed by code)</p>
            <ul class="space-y-2 mb-6">${findings}</ul>` : ""}

            ${highs ? `
            <p class="text-slate-400 text-xs uppercase tracking-wide mb-3 font-medium">Analyst response to each HIGH finding</p>
            <ul class="space-y-2 mb-6">${highs}</ul>` : ""}

            ${notes ? `
            <p class="text-slate-400 text-xs uppercase tracking-wide mb-2 font-medium">Validator notes</p>
            <ul class="space-y-1">${notes}</ul>` : ""}
        </div>`;
    },
    // ── 2. EMAIL METADATA ─────────────────────────────────────────────────
    renderEmailMeta() {
        const p   = this.report.parsed || {};
        const spf = p.spf  || "none";
        const dkim= p.dkim || "none";
        const dmarc=p.dmarc|| "none";

        const authBadge = (val) => {
            const colors = {
                pass:     "bg-green-500/20 text-green-400 border-green-500",
                fail:     "bg-red-500/20 text-red-400 border-red-500",
                softfail: "bg-yellow-500/20 text-yellow-400 border-yellow-500",
                none:     "bg-slate-700 text-slate-400 border-slate-600",
            };
            const cls = colors[val?.toLowerCase()] || colors.none;
            return `<span class="px-2 py-0.5 rounded border text-xs font-mono font-bold ${cls}">${(val||"none").toUpperCase()}</span>`;
        };

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-4">📋 Email Information</h2>
            <div class="grid md:grid-cols-2 gap-4 text-sm">
                <div class="space-y-3">
                    ${this.metaRow("From",        p.from_addr    || "—")}
                    ${this.metaRow("Domain",      p.from_domain  || "—")}
                    ${this.metaRow("Reply-To",    p.reply_to     || "None")}
                    ${this.metaRow("Hops",        p.received_hops ?? "—")}
                    ${this.metaRow("Attachments", p.attachment_count ?? 0)}
                </div>
                <div>
                    <p class="text-slate-400 text-xs uppercase tracking-wide mb-3 font-medium">Authentication</p>
                    <div class="space-y-2">
                        <div class="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2.5">
                            <span class="text-slate-300">SPF</span>
                            ${authBadge(spf)}
                        </div>
                        <div class="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2.5">
                            <span class="text-slate-300">DKIM</span>
                            ${authBadge(dkim)}
                        </div>
                        <div class="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2.5">
                            <span class="text-slate-300">DMARC</span>
                            ${authBadge(dmarc)}
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
    },

    metaRow(label, value) {
        return `
        <div class="flex gap-2">
            <span class="text-slate-500 w-28 flex-shrink-0">${label}</span>
            <span class="text-white break-all">${this._esc(value)}</span>
        </div>`;
    },

    // ── 3. FLAGS ──────────────────────────────────────────────────────────
    renderFlags() {
        const flags = this.report.flags || [];
        if (!flags.length) return "";

        const items = flags.map(f => {
            const isWarn = f.includes("⚠") || f.includes("fail") || f.includes("FAIL");
            const color  = isWarn ? "border-red-500/40 bg-red-500/10 text-red-300"
                                  : "border-slate-700 bg-slate-800/50 text-slate-300";
            return `<li class="flex items-start gap-2 px-4 py-3 rounded-lg border ${color} text-sm">
                <span class="flex-shrink-0 mt-0.5">${isWarn ? "⚠️" : "ℹ️"}</span>
                <span>${this._esc(f)}</span>
            </li>`;
        }).join("");

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-4">🚩 Detection Flags (${flags.length})</h2>
            <ul class="space-y-2">${items}</ul>
        </div>`;
    },

    // ── 4. AI SCORES ──────────────────────────────────────────────────────
    renderAIScores() {
        const ts = this.report.text_structural || {};
        const deb = ts.deberta || {};
        const xgb = ts.xgboost || {};
        const fusion = ts.fusion || {};
        const agree = ts.agreement;

        const scoreBar = (prob, label, verdict) => {

            const pct =
                prob !== undefined
                    ? (prob * 100).toFixed(1)
                    : null;

            const color =
                prob > 0.65
                    ? "bg-red-500"
                    : prob < 0.40
                        ? "bg-green-500"
                        : "bg-yellow-400";

            const txtCls =
                Utils.verdictColor(verdict);

            return `
            <div class="bg-slate-800 rounded-xl p-4">

                <div class="flex items-center justify-between mb-3">

                    <span class="text-slate-300 font-medium text-sm">
                        ${label}
                    </span>

                    <span class="${txtCls} font-bold text-sm">
                        ${verdict || "—"}
                    </span>

                </div>

                <div class="flex items-center gap-3">

                    <div class="flex-1 h-3 bg-slate-700 rounded-full overflow-hidden">

                        <div
                            class="${color} h-full rounded-full transition-all duration-700"
                            style="width:${pct || 0}%">
                        </div>

                    </div>

                    <span class="text-white font-mono font-bold text-sm w-14 text-right">
                        ${pct !== null ? pct + "%" : "—"}
                    </span>

                </div>

            </div>`;
        };

        const agreeBadge =
            agree === false

                ? `<span class="px-3 py-1 bg-yellow-500/20 border border-yellow-500 text-yellow-400 text-xs rounded-full">
                     ⚠ Models Disagree — Fusion applied
                   </span>`

                : `<span class="px-3 py-1 bg-green-500/20 border border-green-500 text-green-400 text-xs rounded-full">
                     ✓ Models Agree
                   </span>`;

        const aiVerdict =
            fusion.ai_verdict ||
            fusion.verdict ||
            "UNKNOWN";

        const aiProbability =
            fusion.ai_probability !== undefined
                ? Number(fusion.ai_probability)
                : Number(fusion.fused_probability || 0);

        const senderTrusted =
            fusion.sender_trusted === true ||
            fusion.sender_verification === "VERIFIED";

        let finalVerdict =
            this.report.final_verdict || "UNKNOWN";

        // Frontend fallback if backend still sends UNKNOWN.
        if (finalVerdict === "UNKNOWN" || !finalVerdict) {

            if (senderTrusted) {

                finalVerdict =
                    aiProbability >= 0.90
                        ? "HUMAN_REVIEW"
                        : "LEGITIMATE";

            } else if (aiVerdict === "PHISHING") {

                finalVerdict =
                    aiProbability >= 0.90
                        ? "PHISHING"
                        : "HUMAN_REVIEW";

            } else if (aiVerdict === "LEGITIMATE") {

                finalVerdict = "LEGITIMATE";

            } else {

                finalVerdict = "HUMAN_REVIEW";
            }
        }

        const finalReason =
            this.report.decision_reason ||
            fusion.decision_reason ||
            "";

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">

            <div class="flex items-center justify-between mb-5">

                <h2 class="text-white font-bold text-lg">
                    🧪 Local Model Evidence (advisory)
                </h2>

                ${agreeBadge}

            </div>

            <div class="space-y-3">

                ${scoreBar(
                    deb.probability,
                    "DeBERTa V12 (Language + Behavior)",
                    deb.verdict
                )}

                ${scoreBar(
                    xgb.probability,
                    "XGBoost V3 (Header Structure)",
                    xgb.verdict
                )}

            </div>

            <!-- Local Fusion Score (advisory) -->

            <div class="mt-4 p-4 rounded-xl ${Utils.verdictBg(aiVerdict)}">

                <div class="flex items-center justify-between">

                    <div>

                        <p class="text-slate-300 text-sm font-medium">
                            Local Fusion Score (advisory)
                        </p>

                        <p class="text-slate-400 text-xs mt-0.5">
                            Combined local model score. Input to the AI analyst, not the final verdict
                        </p>

                    </div>

                    <div class="text-right">

                        <p class="${Utils.verdictColor(aiVerdict)} text-2xl font-extrabold">
                            ${aiVerdict}
                        </p>

                        <p class="text-slate-400 text-xs font-mono">
                            ${(aiProbability * 100).toFixed(2)}% phishing probability
                        </p>

                    </div>

                </div>

            </div>

            <!-- Final Decision -->

            <div class="mt-3 p-4 rounded-xl bg-slate-800 border border-slate-700">

                <div class="flex items-center justify-between">

                    <div>

                        <p class="text-slate-300 text-sm font-medium">
                            Final Decision
                        </p>

                        ${
                            finalReason
                                ? `<p class="text-slate-500 text-xs mt-1">
                                    ${finalReason}
                                   </p>`
                                : ""
                        }

                    </div>

                    <span class="${Utils.verdictColor(finalVerdict)} text-xl font-bold">
                        ${finalVerdict}
                    </span>

                </div>

            </div>

        </div>`;
    },

    // ── 5. SHAP EXPLAINABILITY ────────────────────────────────────────────
    renderSHAP() {
        const exp = this.report.explainability || {};
        const top = exp.top_features || [];
        if (!top.length) return "";

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-2">📊 Why This Verdict? (SHAP)</h2>
            <p class="text-slate-400 text-sm mb-5">
                Red bars pushed toward phishing. Green bars pushed toward legitimate.
                Base score: <span class="font-mono text-white">${exp.base_value?.toFixed(4) || "—"}</span>
            </p>
            <div style="height:320px">
                <canvas id="shap-chart"></canvas>
            </div>
            <!-- Summary bullets -->
            <ul class="mt-5 space-y-1.5">
                ${(exp.summary || []).map(s => `
                    <li class="text-slate-400 text-sm flex items-start gap-2">
                        <span class="text-indigo-400 flex-shrink-0">›</span>${s}
                    </li>`).join("")}
            </ul>
        </div>`;
    },

    initSHAPChart() {
        const exp   = this.report.explainability || {};
        const top   = exp.top_features || [];
        if (!top.length) return;

        const canvas = document.getElementById("shap-chart");
        if (!canvas) return;

        const labels = top.map(f => f.feature);
        const values = top.map(f => f.shap_value);
        const colors = top.map(f =>
            f.direction === "phishing" ? "rgba(239,68,68,0.8)" : "rgba(34,197,94,0.8)"
        );

        new Chart(canvas, {
            type: "bar",
            data: {
                labels,
                datasets: [{
                    label: "SHAP Value",
                    data:  values,
                    backgroundColor: colors,
                    borderRadius: 6,
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: ctx => {
                                const f = top[ctx.dataIndex];
                                return [
                                    ` SHAP: ${ctx.raw.toFixed(4)}`,
                                    ` Direction: ${f.direction}`,
                                    ` Raw value: ${f.raw_value}`,
                                ];
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid:  { color: "rgba(255,255,255,0.05)" },
                        ticks: { color: "#94a3b8", font: { size: 11 } },
                    },
                    y: {
                        grid:  { display: false },
                        ticks: { color: "#cbd5e1", font: { size: 11 } },
                    }
                }
            }
        });
    },

    // ── 6. INTENT ─────────────────────────────────────────────────────────
    renderIntent() {
        const intent = this.report.nlp_extra?.intent || {};
        const all    = intent.all_intents || [];
        if (!all.length) return "";

        const bars = all.map(i => {
            const pct   = (i.score * 100).toFixed(1);
            const isTop = i.label === intent.top_intent;
            return `
            <div class="space-y-1">
                <div class="flex justify-between text-xs">
                    <span class="${isTop ? "text-white font-medium" : "text-slate-400"}">${i.label}</span>
                    <span class="text-slate-400 font-mono">${pct}%</span>
                </div>
                <div class="h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div class="${isTop ? "bg-indigo-500" : "bg-slate-600"} h-full rounded-full"
                         style="width:${pct}%"></div>
                </div>
            </div>`;
        }).join("");

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-2">🎯 Intent Classification</h2>
            <div class="flex items-center gap-3 mb-5">
                <span class="px-3 py-1.5 bg-indigo-600/30 border border-indigo-500 text-indigo-300 rounded-lg text-sm font-medium">
                    ${intent.top_intent || "—"}
                </span>
                <span class="text-slate-400 text-sm">
                    ${(intent.confidence * 100).toFixed(1)}% confidence
                </span>
            </div>
            <div class="space-y-3">${bars}</div>
        </div>`;
    },

    // ── 7. FORENSICS ──────────────────────────────────────────────────────
    renderForensics() {
        const f = this.report.forensics || {};

        const sections = [
            this.renderForensicCard("🔐 Auth Headers",    f.auth_headers),
            this.renderForensicCard("📮 Address Mismatch", f.address_mismatch),
            this.renderForensicCard("🔡 Typosquatting",    f.typosquat),
            this.renderForensicCard("🔗 URL Reputation",   f.url_reputation),
            this.renderForensicCard("📅 Domain Age (WHOIS)",f.whois),
        ].join("");

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-5">🔍 Forensics Analysis</h2>
            <div class="space-y-4">${sections}</div>
        </div>`;
    },

    renderForensicCard(title, data) {
        if (!data) return "";
        const verdict = data.verdict || "none";
        const badge   = Utils.severityBadge(verdict);
        const findings= data.findings || data.domains || [];

        const rows = findings.map(f => {
            const label = f.check || f.domain || f.url || f.field || "";
            const result= f.result || f.risk  || "";
            const meaning=f.meaning|| f.reasons?.join(", ") || "";
            return `
            <div class="pl-4 border-l-2 border-slate-700 py-1">
                <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-slate-200 text-sm font-medium">${label}</span>
                    ${result ? Utils.severityBadge(result) : ""}
                </div>
                ${meaning ? `<p class="text-slate-500 text-xs mt-0.5">${meaning}</p>` : ""}
            </div>`;
        }).join("");

        return `
        <div class="bg-slate-800/40 rounded-xl p-4">
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-slate-200 font-medium text-sm">${title}</h3>
                ${badge}
            </div>
            ${rows || `<p class="text-slate-600 text-xs">No findings</p>`}
        </div>`;
    },

    // ── 8. GEOIP ──────────────────────────────────────────────────────────
    renderGeoIP() {
        const g = this.report.geoip || {};
        if (!g.originating_ip) return "";

        const loc    = g.location || {};
        const isRisk = g.high_risk_country;

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-5">🌍 Origin & GeoIP</h2>
            <div class="grid md:grid-cols-2 gap-6">
                <!-- Details -->
                <div class="space-y-3">
                    <div class="p-4 bg-slate-800 rounded-xl space-y-2 text-sm">
                        ${this.metaRow("Originating IP", g.originating_ip || "—")}
                        ${this.metaRow("Country",  `${loc.country || "—"} ${isRisk ? "⚠️ HIGH RISK" : ""}`)}
                        ${this.metaRow("Region",   loc.region || "—")}
                        ${this.metaRow("City",     loc.city   || "—")}
                        ${this.metaRow("ISP",      g.isp      || "—")}
                        ${this.metaRow("Org",      g.org      || "—")}
                    </div>
                    ${isRisk ? `
                    <div class="p-3 bg-red-500/20 border border-red-500/40 rounded-lg text-red-300 text-sm">
                        ⚠️ Origin IP is from a high-risk country associated with phishing campaigns.
                    </div>` : ""}
                </div>
                <!-- Map -->
                <div>
                    <a id="geoip-map-link"
                    href="https://www.google.com/maps?q=${loc.lat},${loc.lon}"
                    target="_blank"
                    title="Click to open in Google Maps"
                    class="block relative group">
                        <div id="geoip-map" class="w-full h-52 rounded-xl overflow-hidden border border-slate-700"></div>
                        <div class="absolute inset-0 bg-black/0 group-hover:bg-black/30 rounded-xl transition flex items-center justify-center">
                            <span class="opacity-0 group-hover:opacity-100 transition bg-white text-slate-900 text-xs font-medium px-3 py-1.5 rounded-full">
                                🗺 Open in Google Maps
                            </span>
                        </div>
                    </a>
                </div>
            </div>
        </div>`;
    },

    initGeoIPMap() {
        const g   = this.report.geoip || {};
        const loc = g.location || {};
        if (!loc.lat || !loc.lon) return;

        const map = L.map("geoip-map", { zoomControl: true }).setView([loc.lat, loc.lon], 5);
        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: "© OpenStreetMap",
        }).addTo(map);

        const color  = g.high_risk_country ? "red" : "blue";
        const marker = L.circleMarker([loc.lat, loc.lon], {
            radius: 10, fillColor: color, color: "#fff",
            weight: 2, opacity: 1, fillOpacity: 0.8
        }).addTo(map);
        marker.bindPopup(`
            <b>${g.originating_ip}</b><br/>
            ${loc.city}, ${loc.country}<br/>
            ${g.isp}<br/>
            <a href="https://www.google.com/maps?q=${loc.lat},${loc.lon}"
            target="_blank" style="color:#6366f1">Open in Google Maps ↗</a>
        `).openPopup();
    },

    // ── 9. VISION ─────────────────────────────────────────────────────────
    renderVision() {
        const v = this.report.vision || {};
        const ocr  = v.ocr  || {};
        const qr   = v.qr   || {};
        const logo = v.logo || {};

        const ocrSection = `
        <div class="bg-slate-800/40 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-slate-200 font-medium text-sm">🔤 OCR (Image Text)</h3>
                ${ocr.has_image_text
                    ? `<span class="text-xs bg-yellow-500/20 text-yellow-400 border border-yellow-500 px-2 py-0.5 rounded">Text Found</span>`
                    : `<span class="text-xs text-slate-500">No images</span>`}
            </div>
            ${ocr.has_image_text
                ? `<p class="text-slate-300 text-sm bg-slate-800 rounded-lg p-3 font-mono break-all">${ocr.ocr_text}</p>`
                : `<p class="text-slate-600 text-xs">No image text detected</p>`}
        </div>`;

        const qrSection = `
        <div class="bg-slate-800/40 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-slate-200 font-medium text-sm">📱 QR Code (Quishing)</h3>
                ${qr.quishing_suspected
                    ? `<span class="text-xs bg-red-500/20 text-red-400 border border-red-500 px-2 py-0.5 rounded">⚠ QR URLs Found</span>`
                    : `<span class="text-xs text-slate-500">No QR codes</span>`}
            </div>
            ${qr.qr_urls?.length
                ? qr.qr_urls.map(u => `<p class="text-red-300 text-xs font-mono break-all mt-1">${u}</p>`).join("")
                : `<p class="text-slate-600 text-xs">No QR codes detected</p>`}
        </div>`;

        const logoSection = `
        <div class="bg-slate-800/40 rounded-xl p-4">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-slate-200 font-medium text-sm">🏷️ Brand Logo Spoofing</h3>
                ${logo.spoofing_detected
                    ? `<span class="text-xs bg-red-500/20 text-red-400 border border-red-500 px-2 py-0.5 rounded">⚠ Spoofing Detected</span>`
                    : `<span class="text-xs text-green-400">Clean</span>`}
            </div>
            ${logo.spoofing_brands?.length
                ? `<p class="text-red-300 text-sm">Brands spoofed: ${logo.spoofing_brands.join(", ")}</p>`
                : `<p class="text-slate-600 text-xs">No brand spoofing detected</p>`}
        </div>`;

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-4">👁️ Vision Analysis</h2>
            <div class="space-y-3">
                ${ocrSection}
                ${qrSection}
                ${logoSection}
            </div>
        </div>`;
    },

    // ── 10. ATTACHMENTS ───────────────────────────────────────────────────
    renderAttachments() {
        const att  = this.report.attachments || {};
        const pdf  = att.pdf    || {};
        const off  = att.office || {};

        if (!pdf.pdf_count && !off.office_count) return "";

        const renderResults = (results) => results.map(r => `
        <div class="bg-slate-800 rounded-lg p-3 text-sm">
            <div class="flex items-center justify-between mb-1">
                <span class="text-slate-200 font-medium">📄 ${r.filename}</span>
                ${Utils.severityBadge(r.verdict?.toLowerCase())}
            </div>
            ${r.risk_reasons?.length
                ? r.risk_reasons.map(rr => `<p class="text-red-300 text-xs mt-1">• ${rr}</p>`).join("")
                : ""}
        </div>`).join("");

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <h2 class="text-white font-bold text-lg mb-4">📎 Attachment Scan</h2>
            <div class="space-y-3">
                ${pdf.pdf_count > 0 ? `
                <div>
                    <p class="text-slate-400 text-xs uppercase tracking-wide mb-2">PDF Files (${pdf.pdf_count})</p>
                    ${renderResults(pdf.results || [])}
                </div>` : ""}
                ${off.office_count > 0 ? `
                <div>
                    <p class="text-slate-400 text-xs uppercase tracking-wide mb-2">Office Files (${off.office_count})</p>
                    ${renderResults(off.results || [])}
                </div>` : ""}
            </div>
        </div>`;
    },

    // ── 11. SMTP CHAIN ────────────────────────────────────────────────────
    renderSMTPChain() {
        const smtp = this.report.smtp_chain || {};
        const role = this.role;

        const anomalySection = smtp.anomalies?.length ? `
        <div class="mt-3 space-y-1">
            ${smtp.anomalies.map(a => `
            <p class="text-yellow-300 text-xs flex items-start gap-2">
                <span class="flex-shrink-0">⚠</span>${a}
            </p>`).join("")}
        </div>` : "";

        // Cyber tier sees full hop details
        const hopDetails = (role === CONFIG.ROLES.CYBER) ? `
        <div class="mt-4">
            <p class="text-slate-400 text-xs uppercase tracking-wide mb-2">Full Hop Chain</p>
            <div class="space-y-2">
                ${(smtp.hops || []).map(h => `
                <div class="bg-slate-800 rounded-lg p-3 text-xs font-mono">
                    <p class="text-indigo-400 mb-1">Hop ${h.hop_index}</p>
                    <p class="text-slate-400 break-all">${h.header_snippet}</p>
                    ${h.public_ips?.length
                        ? `<p class="text-green-400 mt-1">Public IPs: ${h.public_ips.join(", ")}</p>`
                        : ""}
                </div>`).join("")}
            </div>
        </div>` : "";

        const fcrdns = smtp.fcrdns_results || [];
        const fcrdnsSection = fcrdns.length ? `
        <div class="mt-3">
            <p class="text-slate-400 text-xs uppercase tracking-wide mb-2">FCrDNS Validation</p>
            ${fcrdns.map(r => `
            <div class="flex items-center gap-3 text-xs py-1.5 border-b border-slate-800">
                <span class="font-mono text-slate-300 w-36 flex-shrink-0">${r.ip}</span>
                <span class="${r.fcrdns_pass === true ? "text-green-400" : r.fcrdns_pass === false ? "text-red-400" : "text-slate-500"}">
                    ${r.fcrdns_pass === true ? "✓ PASS" : r.fcrdns_pass === false ? "✗ FAIL" : "? Unknown"}
                </span>
                <span class="text-slate-500 truncate">${r.rdns_hostname || r.error || ""}</span>
            </div>`).join("")}
        </div>` : "";

        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-white font-bold text-lg">⛓ SMTP Chain Traversal</h2>
                ${smtp.chain_suspicious
                    ? `<span class="text-xs bg-red-500/20 text-red-400 border border-red-500 px-3 py-1 rounded-full">⚠ Suspicious Chain</span>`
                    : `<span class="text-xs bg-green-500/20 text-green-400 border border-green-500 px-3 py-1 rounded-full">✓ Clean Chain</span>`}
            </div>
            <div class="grid grid-cols-2 gap-3 mb-4">
                <div class="bg-slate-800 rounded-xl p-3 text-center">
                    <p class="text-3xl font-bold text-white">${smtp.hop_count ?? "—"}</p>
                    <p class="text-slate-400 text-xs mt-1">Relay Hops</p>
                </div>
                <div class="bg-slate-800 rounded-xl p-3 text-center">
                    <p class="text-lg font-mono font-bold text-indigo-300 truncate">${smtp.originating_ip || "—"}</p>
                    <p class="text-slate-400 text-xs mt-1">Originating IP</p>
                </div>
            </div>
            ${anomalySection}
            ${fcrdnsSection}
            ${hopDetails}
        </div>`;
    },

    // ── 12. BLOCKCHAIN ────────────────────────────────────────────────────
    renderBlockchain() {
        const bc = this.report.blockchain || {};

        const statusBadge = bc.tx_hash
            ? `<span class="px-3 py-1 bg-green-500/20 border border-green-500 text-green-400 text-xs rounded-full font-medium">✓ Anchored on Sepolia</span>`
            : `<span class="px-3 py-1 bg-yellow-500/20 border border-yellow-500 text-yellow-400 text-xs rounded-full font-medium animate-pulse">⏳ Anchoring...</span>`;

        const etherscanBtn = bc.polygonscan_url ? `
        <a href="${bc.polygonscan_url}" target="_blank"
            class="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition">
            View on Etherscan ↗
        </a>` : `
        <button disabled class="inline-flex items-center gap-2 bg-slate-700 text-slate-400 px-4 py-2 rounded-lg text-sm cursor-not-allowed">
            Waiting for confirmation...
        </button>`;

        const ipfsBtn = bc.ipfs_cid ? `
        <a href="https://gateway.pinata.cloud/ipfs/${bc.ipfs_cid}" target="_blank"
            class="inline-flex items-center gap-2 border border-slate-600 hover:border-slate-400 text-slate-300 hover:text-white px-4 py-2 rounded-lg text-sm transition">
            View on IPFS ↗
        </a>` : "";

        const laws = (bc.law_reference || []).map(l => `
        <span class="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-400">⚖️ ${l}</span>
        `).join("");

        return `
        <div class="bg-slate-900 border border-indigo-500/30 rounded-2xl p-6 mb-6">
            <div class="flex items-center justify-between mb-5">
                <h2 class="text-white font-bold text-lg">⛓️ Blockchain Anchor</h2>
                ${statusBadge}
            </div>

            <div class="space-y-3 text-sm mb-5">
                <div class="flex items-start gap-3 bg-slate-800 rounded-xl p-3">
                    <span class="text-slate-500 w-28 flex-shrink-0">Analysis ID</span>
                    <span class="text-white font-mono text-xs break-all">${bc.analysis_id || "—"}</span>
                </div>
                <div class="flex items-start gap-3 bg-slate-800 rounded-xl p-3">
                    <span class="text-slate-500 w-28 flex-shrink-0">SHA-256 Hash</span>
                    <div class="flex-1 min-w-0">
                        <span class="text-indigo-300 font-mono text-xs break-all" id="report-hash-val">
                            ${bc.report_hash || "—"}
                        </span>
                        <button onclick="Utils.copyToClipboard('${bc.report_hash}', this)"
                            class="ml-2 text-xs text-slate-500 hover:text-white transition">Copy</button>
                    </div>
                </div>
                <div class="flex items-start gap-3 bg-slate-800 rounded-xl p-3">
                    <span class="text-slate-500 w-28 flex-shrink-0">IPFS CID</span>
                    <span id="ipfs-cid-val" class="text-slate-300 font-mono text-xs break-all">
                        ${bc.ipfs_cid || "Pending..."}
                    </span>
                </div>
                <div class="flex items-start gap-3 bg-slate-800 rounded-xl p-3">
                    <span class="text-slate-500 w-28 flex-shrink-0">TX Hash</span>
                    <span id="tx-hash-val" class="text-slate-300 font-mono text-xs break-all">
                        ${bc.tx_hash || "Pending..."}
                    </span>
                </div>
            </div>

            <!-- Action buttons -->
            <div class="flex flex-wrap gap-3 mb-5" id="blockchain-btns">
                ${etherscanBtn}
                ${ipfsBtn}
            </div>

            <!-- How to verify -->
            <div class="bg-slate-800/50 border border-slate-700 rounded-xl p-4 text-xs text-slate-400 space-y-1">
                <p class="text-slate-300 font-medium text-sm mb-2">🔍 How to Verify Tamper-Proof Integrity</p>
                <p>1. Click "View on IPFS" → download the full JSON report</p>
                <p>2. Compute SHA-256 of the downloaded file</p>
                <p>3. Compare it to the hash shown above (on-chain)</p>
                <p>4. If they match → report was never modified since analysis ✓</p>
            </div>

            <!-- Legal badges -->
            <div class="flex flex-wrap gap-2 mt-4">
                ${laws}
            </div>
        </div>`;
    },

    // ── 13. DOWNLOAD BAR ──────────────────────────────────────────────────
    renderDownloadBar() {
        return `
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 mb-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div>
                <p class="text-white font-semibold">Download Forensic Report</p>
                <p class="text-slate-400 text-sm">Formal structured report: determination, findings, indicators, IP addresses, map links and evidence integrity. Text only, no screenshots.</p>
            </div>
            <div class="flex flex-wrap gap-3 flex-shrink-0">
                <button onclick="ReportRenderer.downloadText()"
                    class="bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-5 py-3 rounded-xl transition">
                    📄 Download .txt
                </button>
                <button onclick="ReportRenderer.downloadPDF()"
                    class="border border-slate-600 hover:border-slate-400 text-slate-200 font-medium px-5 py-3 rounded-xl transition">
                    📥 Download PDF
                </button>
            </div>
        </div>`;
    },

    // ── 14. BLOCKCHAIN POLLING ────────────────────────────────────────────
    // If blockchain not yet anchored, polls every 5s until tx_hash appears
    async pollBlockchain() {
        const bc = this.report.blockchain || {};
        if (bc.tx_hash) return;   // already done

        const id = bc.analysis_id;
        if (!id) return;

        let attempts = 0;
        const max    = 24;   // 2 minutes max       

        const poll = async () => {
            attempts++;
            try {
                const row = await API.getAnalysis(id);

                // ── STOP: blockchain succeeded ────────────────────────────────
                if (row?.tx_hash) {
                    this._updateBlockchainUI(row);
                    Utils.toast("✅ Blockchain anchor confirmed!", "success");
                    return;
                }

                // ── STOP: blockchain failed permanently ───────────────────────
                if (row?.anchor_error) {
                    const btns = document.getElementById("blockchain-btns");
                    if (btns) {
                        btns.innerHTML = `
                        <div class="text-sm text-red-400 flex items-center gap-2">
                            ⚠ Blockchain anchor failed — RPC rate limit.
                            Report hash is still valid and stored in Supabase.
                        </div>`;
                    }
                    // Still show IPFS if available
                    if (row.ipfs_cid) {
                        const ipfsEl = document.getElementById("ipfs-cid-val");
                        if (ipfsEl) ipfsEl.textContent = row.ipfs_cid;
                    }
                    console.warn("Blockchain anchor failed:", row.anchor_error);
                    return;   // stop polling
                }

            } catch (err) {
                console.warn("Polling error:", err.message);
            }

            if (attempts < max) {
                setTimeout(poll, 5000);
            } else {
                console.warn("Blockchain polling timed out after 2 minutes");
            }
        };

        setTimeout(poll, 5000);
    },

    _updateBlockchainUI(row) {
        const ipfsEl = document.getElementById("ipfs-cid-val");
        const txEl   = document.getElementById("tx-hash-val");
        const btns   = document.getElementById("blockchain-btns");

        if (ipfsEl) ipfsEl.textContent = row.ipfs_cid || "—";
        if (txEl)   txEl.textContent   = row.tx_hash  || "—";
        if (btns) {
            btns.innerHTML = `
            <a href="https://sepolia.etherscan.io/tx/${row.tx_hash}" target="_blank"
                class="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition">
                View on Etherscan ↗
            </a>
            <a href="https://gateway.pinata.cloud/ipfs/${row.ipfs_cid}" target="_blank"
                class="inline-flex items-center gap-2 border border-slate-600 hover:border-slate-400 text-slate-300 px-4 py-2 rounded-lg text-sm transition">
                View on IPFS ↗
            </a>`;
        }
    },

    // ── 15. REPORT DOWNLOAD (.txt and PDF, same content) ──────────────────
    // The backend writes the report. We ask it again at download time so the
    // blockchain fields are filled in even if anchoring finished after the scan.
    async _getReportText() {
        const id = this.report?.blockchain?.analysis_id;
        if (id) {
            try {
                const text = await API.getReportText(id);
                if (text && text.length > 200) return text;
            } catch (e) {
                console.warn("Fresh report fetch failed, using the copy from the scan:", e.message);
            }
        }
        if (this.report?.report_text) return this.report.report_text;
        throw new Error("The report text is not available. Please run the analysis again.");
    },

    _reportBaseName() {
        const id = this.report?.blockchain?.analysis_id;
        return this.report?.report_filename
            ? this.report.report_filename.replace(/\.txt$/i, "")
            : `EmailGuardAI_Forensic_Report_${id || Date.now()}`;
    },

    async downloadText() {
        try {
            Utils.toast("Preparing report...", "info");
            const text = await this._getReportText();
            const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement("a");
            a.href = url;
            a.download = this._reportBaseName() + ".txt";
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 2000);
            Utils.toast("✅ Report downloaded", "success");
        } catch (err) {
            console.error("Report error:", err);
            Utils.toast("Report download failed: " + err.message, "error");
        }
    },

    async downloadPDF() {
        try {
            if (!window.jspdf) throw new Error("PDF library did not load. Use the .txt download.");
            Utils.toast("Generating PDF report...", "info");

            const text  = await this._getReportText();
            const lines = text.replace(/\r/g, "").split("\n");

            const { jsPDF } = window.jspdf;
            const pdf = new jsPDF("p", "mm", "a4");
            const W = pdf.internal.pageSize.getWidth();
            const H = pdf.internal.pageSize.getHeight();
            const ML = 20, TOP = 20, BOTTOM = 18, LH = 4.0, FS = 9;
            const maxY = H - BOTTOM;

            const id = this.report?.blockchain?.analysis_id || "";
            pdf.setProperties({
                title:   "EmailGuard AI - Email Threat Forensic Analysis Report",
                subject: id ? `Analysis ${id}` : "Forensic analysis report",
                author:  "EmailGuard AI",
                creator: "EmailGuard AI",
            });

            pdf.setFont("courier", "normal");
            pdf.setFontSize(FS);
            pdf.setTextColor(20, 20, 20);

            let y = TOP;
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const next = lines[i + 1] || "";
                const isHeading = /^SECTION \d+\./.test(line) ||
                                  (line.trim() && /^\s*-{3,}\s*$/.test(next) && !/^\s*-{3,}\s*$/.test(line));

                // keep a heading together with the lines under it
                if (isHeading && y + LH * 4 > maxY) { pdf.addPage(); y = TOP; }
                if (y + LH > maxY)                  { pdf.addPage(); y = TOP; }

                pdf.setFont("courier", isHeading ? "bold" : "normal");
                if (line) pdf.text(line, ML, y);
                y += LH;
            }

            // running header + footer, written once the page count is known
            const pages = pdf.getNumberOfPages();
            for (let p = 1; p <= pages; p++) {
                pdf.setPage(p);
                pdf.setFont("helvetica", "normal");
                pdf.setFontSize(7.5);
                pdf.setTextColor(110, 110, 110);
                pdf.text("EmailGuard AI - Email Threat Forensic Analysis Report", ML, 11);
                if (id) pdf.text(`ID ${id}`, W - ML, 11, { align: "right" });
                pdf.setDrawColor(200, 200, 200);
                pdf.line(ML, 13, W - ML, 13);
                pdf.line(ML, H - 13, W - ML, H - 13);
                pdf.text("EmailGuard AI | founder@emailguardai.me", ML, H - 8);
                pdf.text(`Page ${p} of ${pages}`, W - ML, H - 8, { align: "right" });
            }

            pdf.save(this._reportBaseName() + ".pdf");
            Utils.toast("✅ PDF downloaded successfully!", "success");
        } catch (err) {
            console.error("PDF error:", err);
            Utils.toast("PDF generation failed: " + err.message, "error");
        }
    },
};