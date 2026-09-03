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

    // ── THEORY GENERATOR ──────────────────────────────────────────────────
    getFinalAssessmentTheory() {
        const report = this.report || {};
        const ts = report.text_structural || {};
        const fusion = ts.fusion || {};

        let verdict = report.final_verdict || "UNKNOWN";

        // Never expose UNKNOWN to the user.
        if (verdict === "UNKNOWN") {
            verdict = "HUMAN_REVIEW";
        }

        const aiVerdict =
            fusion.ai_verdict ||
            fusion.verdict ||
            "UNKNOWN";

        const aiProbability =
            fusion.ai_probability !== undefined
                ? Number(fusion.ai_probability)
                : Number(fusion.fused_probability || 0);

        const phishingPct = (aiProbability * 100).toFixed(2);
        const legitimatePct = ((1 - aiProbability) * 100).toFixed(2);

        const flags = report.flags || [];
        const forensics = report.forensics || {};

        const evidence = [];

        // ─────────────────────────────────────────────
        // AI ASSESSMENT
        // ─────────────────────────────────────────────

        if (aiVerdict === "PHISHING") {

            evidence.push(
                `The AI models identified phishing-like characteristics, resulting in ${phishingPct}% phishing probability.`
            );

        } else if (aiVerdict === "LEGITIMATE") {

            evidence.push(
                `The AI models found the email more consistent with legitimate communication, resulting in ${legitimatePct}% legitimate probability.`
            );
        }

        // ─────────────────────────────────────────────
        // FORENSIC EVIDENCE
        // ─────────────────────────────────────────────

        const mismatch =
            forensics.address_mismatch?.verdict;

        const typosquat =
            forensics.typosquat?.verdict;

        const auth =
            forensics.auth_headers?.verdict;

        const whois =
            forensics.whois?.verdict;

        const urlRep =
            forensics.url_reputation?.verdict;

        // Address mismatch
        if (mismatch === "high") {

            evidence.push(
                "A high address mismatch was detected, which can indicate sender spoofing or routing inconsistencies."
            );

        } else if (mismatch === "medium") {

            evidence.push(
                "A medium address mismatch was detected and should be considered during verification."
            );

        } else if (
            mismatch === "none" ||
            mismatch === "pass"
        ) {

            evidence.push(
                "No significant sender address mismatch was detected."
            );
        }

        // Typosquatting
        if (
            typosquat === "high" ||
            typosquat === "medium"
        ) {

            evidence.push(
                "The domain analysis identified possible brand or domain impersonation indicators."
            );

        } else if (
            typosquat === "none" ||
            typosquat === "pass"
        ) {

            evidence.push(
                "No significant typosquatting indicator was detected."
            );
        }

        // Authentication
        if (
            auth === "trusted" ||
            auth === "pass"
        ) {

            evidence.push(
                "Authentication evidence indicates that the sending infrastructure was authorized for the domain."
            );

        } else if (
            auth === "fail" ||
            auth === "high"
        ) {

            evidence.push(
                "Authentication analysis identified an issue with the claimed sender."
            );
        }

        // WHOIS
        if (whois === "trusted") {

            evidence.push(
                "The domain ownership and WHOIS analysis provided trusted evidence."
            );
        }

        // URL reputation
        if (
            urlRep === "high" ||
            urlRep === "malicious"
        ) {

            evidence.push(
                "URL reputation analysis identified potentially risky or malicious links."
            );

        } else if (
            urlRep === "none" ||
            urlRep === "clean"
        ) {

            evidence.push(
                "No significant URL reputation issue was detected."
            );
        }

        // ─────────────────────────────────────────────
        // EMAIL FLAGS
        // ─────────────────────────────────────────────

        if (flags.length > 0) {

            evidence.push(
                `${flags.length} detection flag(s) were generated during analysis.`
            );
        }

        // ─────────────────────────────────────────────
        // FINAL DECISION THEORY
        // ─────────────────────────────────────────────

        let finalReason = "";

        if (verdict === "PHISHING") {

            finalReason =
                "The email was classified as PHISHING because the combined AI and forensic evidence indicates a sufficiently high security risk. The detected indicators suggest possible deception, impersonation, credential theft, malicious redirection, or other phishing-related activity.";

        } else if (verdict === "LEGITIMATE") {

            finalReason =
                "The email was classified as LEGITIMATE because the available sender, authentication, and forensic evidence supports a genuine communication. Trusted sender verification and supporting security checks provide sufficient confidence for the final legitimate decision.";

        } else {

            finalReason =
                "Human review is required because the AI detected meaningful phishing risk, but the available evidence is not sufficient for an automatic final classification. A human analyst should verify the sender, domain, authentication results, and email context before making the final decision.";

            if (evidence.length === 0) {

                evidence.push(
                    "Manual verification of the sender, domain, authentication results, and email context is recommended."
                );
            }
        }

        return {
            verdict,
            aiVerdict,
            phishingPct,
            legitimatePct,
            finalReason,
            evidence
        };
    },

    // ── 1. VERDICT HERO ───────────────────────────────────────────────────
    renderVerdictHero() {
        const report = this.report || {};
        const fusion = report.text_structural?.fusion || {};

        const aiProbability =
            fusion.ai_probability !== undefined
                ? Number(fusion.ai_probability)
                : Number(fusion.fused_probability || 0);

        const aiVerdict =
            fusion.ai_verdict ||
            fusion.verdict ||
            "UNKNOWN";

        const senderTrusted =
            fusion.sender_trusted === true ||
            fusion.sender_verification === "VERIFIED";

        // Determine display decision if backend returned UNKNOWN.
        let v = report.final_verdict || "UNKNOWN";

        if (v === "UNKNOWN" || !v) {

            if (senderTrusted) {

                if (aiProbability >= 0.90) {
                    v = "HUMAN_REVIEW";
                } else {
                    v = "LEGITIMATE";
                }

            } else if (aiVerdict === "PHISHING") {

                if (aiProbability >= 0.90) {
                    v = "PHISHING";
                } else {
                    v = "HUMAN_REVIEW";
                }

            } else if (aiVerdict === "LEGITIMATE") {

                v = "LEGITIMATE";

            } else {

                v = "HUMAN_REVIEW";
            }
        }

        const icon = Utils.verdictIcon(v);
        const bgCls = Utils.verdictBg(v);
        const txtCls = Utils.verdictColor(v);

        const aiPct =
            (aiProbability * 100).toFixed(2) +
            "% phishing probability";

        const subject =
            report.parsed?.subject ||
            "Unknown Subject";

        const source =
            report.source ||
            "";

        const senderVerification =
            fusion.sender_verification ||
            (senderTrusted ? "VERIFIED" : "NOT VERIFIED");

        const decisionReason =
            report.decision_reason ||
            fusion.decision_reason ||
            "";

        return `
        <div class="${bgCls} rounded-2xl p-8 mb-6 text-center">

            <div class="text-6xl mb-4">${icon}</div>

            <p class="text-slate-400 text-sm uppercase tracking-wider">
                Final Verdict
            </p>

            <h1 class="${txtCls} text-5xl font-extrabold mb-2">
                ${v}
            </h1>

            <div class="mt-5 space-y-2">

                <p class="text-slate-300 text-lg">
                    AI Assessment:
                    <span class="font-bold">${aiVerdict}</span>
                    — ${aiPct}
                </p>

                <p class="text-slate-300 text-sm">
                    Sender Verification:
                    <span class="font-bold ${
                        senderVerification === "VERIFIED"
                            ? "text-green-400"
                            : "text-yellow-400"
                    }">
                        ${senderVerification}
                    </span>
                </p>

                ${
                    decisionReason
                        ? `
                        <p class="text-slate-400 text-xs mt-2">
                            ${decisionReason}
                        </p>
                        `
                        : ""
                }

            </div>

            <p class="text-slate-400 text-sm mt-5 truncate max-w-xl mx-auto"
               title="${subject}">
                📧 ${subject}
            </p>

            ${
                source
                    ? `<p class="text-slate-600 text-xs mt-1">${source}</p>`
                    : ""
            }

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
            <span class="text-white break-all">${value}</span>
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
                <span>${f}</span>
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
                    🤖 AI Analysis
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

            <!-- AI Fusion Assessment -->

            <div class="mt-4 p-4 rounded-xl ${Utils.verdictBg(aiVerdict)}">

                <div class="flex items-center justify-between">

                    <div>

                        <p class="text-slate-300 text-sm font-medium">
                            AI Fusion Assessment
                        </p>

                        <p class="text-slate-400 text-xs mt-0.5">
                            Combined ML model assessment
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
                <p class="text-slate-400 text-sm">Save a PDF copy of this full analysis for your records.</p>
            </div>
            <button onclick="ReportRenderer.downloadPDF()"
                class="flex-shrink-0 bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-6 py-3 rounded-xl transition flex items-center gap-2">
                📥 Download PDF
            </button>
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

    // ── 15. PDF DOWNLOAD ──────────────────────────────────────────────────
    async downloadPDF() {
        const stripEmoji = (str) => str.replace(/[\u{1F300}-\u{1FFFF}|\u{2600}-\u{27BF}]/gu, "").trim();
        Utils.toast("Generating PDF report...", "info");
        try {
            const { jsPDF } = window.jspdf;
            const pdf  = new jsPDF("p", "mm", "a4");
            const W    = pdf.internal.pageSize.getWidth();
            const H    = pdf.internal.pageSize.getHeight();
            const M    = 15;           // margin
            const IW   = W - M * 2;   // inner width
            let   y    = M;
            let   pg   = 1;

            const report = this.report;

            let verdict = report.final_verdict || "UNKNOWN";

            const bc = report.blockchain || {};
            const parsed = report.parsed || {};

            const fusion = report.text_structural?.fusion || {};

            const aiVerdict =
                fusion.ai_verdict ||
                fusion.verdict ||
                "UNKNOWN";

            const aiProbability =
                fusion.ai_probability !== undefined
                    ? Number(fusion.ai_probability)
                    : Number(fusion.fused_probability || 0);

            const phishingPct =
                (aiProbability * 100).toFixed(2);

            const legitimatePct =
                ((1 - aiProbability) * 100).toFixed(2);

            const senderTrusted =
                fusion.sender_trusted === true ||
                fusion.sender_verification === "VERIFIED";

            if (verdict === "UNKNOWN" || !verdict) {

                if (senderTrusted) {

                    verdict =
                        aiProbability >= 0.90
                            ? "HUMAN_REVIEW"
                            : "LEGITIMATE";

                } else if (aiVerdict === "PHISHING") {

                    verdict =
                        aiProbability >= 0.90
                            ? "PHISHING"
                            : "HUMAN_REVIEW";

                } else if (aiVerdict === "LEGITIMATE") {

                    verdict = "LEGITIMATE";

                } else {

                    verdict = "HUMAN_REVIEW";
                }
            }

            const senderVerification =
                fusion.sender_verification ||
                (senderTrusted ? "VERIFIED" : "NOT VERIFIED");

            const decisionReason =
                report.decision_reason ||
                fusion.decision_reason ||
                "";

            // Generate explanation theory for the final decision
            let theoryTitle = "";
            let theoryText = "";

            if (verdict === "PHISHING") {

                theoryTitle = "WHY THIS EMAIL WAS CLASSIFIED AS PHISHING";

                theoryText =
                    "The email was classified as PHISHING because the combined AI " +
                    "and forensic evidence indicates a sufficiently high security risk. " +
                    "The detected characteristics may indicate deception, impersonation, " +
                    "credential theft, malicious redirection, or other phishing-related activity.";

            } else if (verdict === "LEGITIMATE") {

                theoryTitle = "WHY THIS EMAIL WAS CLASSIFIED AS LEGITIMATE";

                theoryText =
                    "The email was classified as LEGITIMATE because the available sender, " +
                    "authentication, and forensic evidence supports a genuine communication. " +
                    "Trusted sender verification and supporting security checks provide " +
                    "sufficient confidence for the final legitimate decision.";

            } else {

                theoryTitle = "WHY HUMAN REVIEW IS REQUIRED";

                theoryText =
                    "Human review is required because the available evidence is not sufficient " +
                    "for an automatic final classification. A human analyst should verify the " +
                    "sender, domain, authentication results, URLs, and email context before " +
                    "making the final decision.";
            }

            // ── Color helpers — explicit r,g,b, no spread ─────────────────────
            const tc = (r,g,b)  => pdf.setTextColor(r,g,b);
            const fc = (r,g,b)  => pdf.setFillColor(r,g,b);
            const dc = (r,g,b)  => pdf.setDrawColor(r,g,b);

            // Named colors
            const C = {
                dark:    [15,  23,  42],
                card:    [30,  41,  59],
                indigo:  [99,  102, 241],
                s300:    [203, 213, 225],
                s400:    [148, 163, 184],
                s500:    [100, 116, 139],
                white:   [255, 255, 255],
                red:     [239, 68,  68 ],
                green:   [34,  197, 94 ],
                yellow:  [245, 158, 11 ],
            };

            const verdictRGB = verdict === "PHISHING"  ? C.red
                            : verdict === "LEGITIMATE" ? C.green
                            : C.yellow;

            // ── Helper: add new page ──────────────────────────────────────────
            const newPage = () => {
                addFooter();
                pdf.addPage();
                pg++;
                y = M;
                fc(...C.dark); pdf.rect(0,0,W,H,"F");
            };

            const checkY = (need) => { if (y + need > H - 22) newPage(); };

            // ── Helper: footer ────────────────────────────────────────────────
            const addFooter = () => {
                fc(20,30,48);   pdf.rect(0, H-12, W, 12, "F");
                dc(...C.indigo);pdf.setLineWidth(0.3);
                pdf.line(0, H-12, W, H-12);
                pdf.setFontSize(6.5); pdf.setFont("helvetica","normal");
                tc(...C.s500);
                pdf.text("© 2026 EmailGuard AI — Built for SIH 2026", M, H-5);
                pdf.text(`Page ${pg}`, W/2, H-5, { align:"center" });
                if (bc.analysis_id) {
                    pdf.text(`ID: ${bc.analysis_id.slice(0,24)}...`, W-M, H-5, { align:"right" });
                }
            };

            // ── Helper: section box ───────────────────────────────────────────
            const section = (title, fn) => {
                checkY(16);
                const sy = y;
                // Header bar
                fc(...C.indigo); pdf.roundedRect(M, y, IW, 7, 2, 2, "F");
                tc(...C.white); pdf.setFontSize(8); pdf.setFont("helvetica","bold");
                pdf.text(title, M+4, y+5);
                y += 9;
                fn();
                y += 4;
                // Box border
                dc(...C.indigo); pdf.setLineWidth(0.3);
                pdf.roundedRect(M, sy, IW, y-sy, 2, 2, "S");
                y += 5;
            };

            // ── Helper: key-value row ─────────────────────────────────────────
            const kv = (label, value, valueColor) => {
                checkY(6);
                pdf.setFontSize(7.5); pdf.setFont("helvetica","bold");
                tc(...C.s400); pdf.text(label+":", M+4, y);
                pdf.setFont("helvetica","normal");
                if (valueColor) tc(...valueColor); else tc(...C.s300);
                const v = String(value || "—");
                pdf.text(v.length > 70 ? v.slice(0,70)+"…" : v, M+40, y);
                y += 6;
            };

            // ── Helper: progress bar ──────────────────────────────────────────
            const bar = (label, prob, verd) => {
                checkY(13);
                const pct   = prob !== undefined ? prob : 0;
                const bColor= pct > 0.65 ? C.red : pct < 0.40 ? C.green : C.yellow;
                const bW    = IW - 70;

                pdf.setFontSize(7.5); pdf.setFont("helvetica","bold");
                tc(...C.s300); pdf.text(label, M+4, y);
                const vc = verd === "PHISHING" ? C.red : verd === "LEGITIMATE" ? C.green : C.yellow;
                tc(...vc); pdf.text(verd||"—", W-M-4, y, {align:"right"});
                y += 5;

                fc(...C.card); pdf.roundedRect(M+4, y-1, bW, 4, 1,1,"F");
                fc(...bColor); pdf.roundedRect(M+4, y-1, bW*pct, 4, 1,1,"F");
                pdf.setFontSize(7); pdf.setFont("helvetica","normal");
                tc(...C.s400); pdf.text(`${(pct*100).toFixed(1)}%`, M+bW+8, y+2);
                y += 8;
            };

            // ════════════════════════════════════════════════════════════════
            // PAGE 1
            // ════════════════════════════════════════════════════════════════
            fc(...C.dark); pdf.rect(0,0,W,H,"F");

            // Header bar
            fc(...C.indigo); pdf.rect(0,0,W,20,"F");
            tc(...C.white);
            pdf.setFontSize(13); pdf.setFont("helvetica","bold");
            pdf.text("EmailGuard AI", M, 9);
            pdf.setFontSize(7.5); pdf.setFont("helvetica","normal");
            pdf.text("AI-Powered Email Threat Detection — Forensic Report", M, 15);
            pdf.text(`Generated: ${new Date().toLocaleString("en-IN")}`, W-M, 9, {align:"right"});
            pdf.text("SIH 2026 — Cybersecurity & Blockchain Track", W-M, 15, {align:"right"});
            y = 28;

            // Verdict banner
            fc(...verdictRGB);
            pdf.roundedRect(M, y, IW, 30, 3, 3, "F");

            tc(...C.white);
            pdf.setFontSize(20);
            pdf.setFont("helvetica", "bold");

            const bannerTxt =
                verdict === "PHISHING"
                    ? "!! PHISHING DETECTED"
                    : verdict === "LEGITIMATE"
                        ? ">> LEGITIMATE EMAIL"
                        : "?? NEEDS HUMAN REVIEW";

            pdf.text(bannerTxt, W / 2, y + 12, { align: "center" });

            pdf.setFontSize(8);
            pdf.setFont("helvetica", "normal");

            if (aiProbability !== undefined) {
                pdf.text(
                    `AI Assessment: ${aiVerdict} — ${(aiProbability * 100).toFixed(2)}% phishing probability`,
                    W / 2,
                    y + 20,
                    { align: "center" }
                );
            }

            pdf.setFontSize(7.5);
            pdf.text(
                `Sender Verification: ${senderVerification}`,
                W / 2,
                y + 26,
                { align: "center" }
            );

            y += 37;

            // Email Info
            section("EMAIL INFORMATION", () => {
                kv("Subject",     parsed.subject      || "—");
                kv("From",        parsed.from_addr    || "—");
                kv("Domain",      parsed.from_domain  || "—");
                const spfC  = parsed.spf  === "pass" ? C.green : C.red;
                const dkimC = parsed.dkim === "pass" ? C.green : C.red;
                const dmC   = parsed.dmarc=== "pass" ? C.green : C.red;
                kv("SPF",   (parsed.spf   ||"none").toUpperCase(), spfC);
                kv("DKIM",  (parsed.dkim  ||"none").toUpperCase(), dkimC);
                kv("DMARC", (parsed.dmarc ||"none").toUpperCase(), dmC);
                kv("Hops",  parsed.received_hops ?? "—");
            });

            // AI Analysis
            section("AI ANALYSIS", () => {
                const ts  = report.text_structural || {};
                bar("DeBERTa V12 (Language + Behavior)", ts.deberta?.probability, ts.deberta?.verdict);
                bar("XGBoost V3 (Header Structure)",     ts.xgboost?.probability, ts.xgboost?.verdict);
                y += 2;

                // AI Fusion Assessment
                const aiVerdictRGB =
                    aiVerdict === "PHISHING"
                        ? C.red
                        : aiVerdict === "LEGITIMATE"
                            ? C.green
                            : C.yellow;

                fc(...aiVerdictRGB);
                pdf.roundedRect(M + 4, y - 2, IW - 8, 11, 2, 2, "F");

                tc(...C.white);
                pdf.setFontSize(9);
                pdf.setFont("helvetica", "bold");

                pdf.text(
                    `AI Fusion Assessment: ${aiVerdict}`,
                    M + 8,
                    y + 5
                );

                pdf.setFontSize(7.5);
                pdf.setFont("helvetica", "normal");

                pdf.text(
                    `${phishingPct}% phishing probability`,
                    W - M - 8,
                    y + 5,
                    { align: "right" }
                );

                y += 14;

                // Final Decision with Sender Verification
                const finalDecisionColor =
                    verdict === "PHISHING"
                        ? C.red
                        : verdict === "LEGITIMATE"
                            ? C.green
                            : C.yellow;

                fc(...finalDecisionColor);
                pdf.roundedRect(M + 4, y - 2, IW - 8, 11, 2, 2, "F");

                tc(...C.white);
                pdf.setFontSize(9);
                pdf.setFont("helvetica", "bold");

                pdf.text(
                    `Final Decision: ${verdict}`,
                    M + 8,
                    y + 5
                );

                pdf.setFontSize(7.5);
                pdf.setFont("helvetica", "normal");

                const verificationLabel =
                    senderTrusted ? "VERIFIED" : "NOT VERIFIED";

                pdf.text(
                    `Sender: ${verificationLabel}`,
                    W - M - 8,
                    y + 5,
                    { align: "right" }
                );

                y += 14;

                if (decisionReason) {
                    kv("Decision Reason", decisionReason);
                }
            });

            // Final Assessment
            section("FINAL ASSESSMENT", () => {

                kv(
                    "AI Assessment",
                    aiVerdict,
                    aiVerdict === "PHISHING"
                        ? C.red
                        : aiVerdict === "LEGITIMATE"
                            ? C.green
                            : C.yellow
                );

                kv(
                    "Phishing Probability",
                    `${phishingPct}%`,
                    C.red
                );

                kv(
                    "Legitimate Probability",
                    `${legitimatePct}%`,
                    C.green
                );

                kv(
                    "Final Decision",
                    verdict,
                    verdict === "PHISHING"
                        ? C.red
                        : verdict === "LEGITIMATE"
                            ? C.green
                            : C.yellow
                );

                kv(
                    "Sender Verification",
                    senderVerification,
                    senderTrusted ? C.green : C.yellow
                );

                if (decisionReason) {

                    pdf.setFontSize(7.5);
                    pdf.setFont("helvetica", "bold");
                    tc(...C.s300);

                    pdf.text(
                        "WHY THIS DECISION?",
                        M + 4,
                        y
                    );

                    y += 6;

                    pdf.setFont("helvetica", "normal");
                    tc(...C.s400);

                    pdf.text(
                        decisionReason,
                        M + 4,
                        y,
                        {
                            maxWidth: IW - 8
                        }
                    );

                    y += 10;
                }

                y += 4;

                // Decision Theory
                pdf.setFontSize(8);
                pdf.setFont("helvetica", "bold");
                tc(...C.s300);

                pdf.text(
                    theoryTitle,
                    M + 4,
                    y
                );

                y += 6;

                pdf.setFontSize(7.5);
                pdf.setFont("helvetica", "normal");
                tc(...C.s400);

                const theoryLines = pdf.splitTextToSize(
                    theoryText,
                    IW - 8
                );

                theoryLines.forEach(line => {

                    checkY(7);

                    pdf.text(
                        line,
                        M + 4,
                        y
                    );

                    y += 4.5;
                });

                y += 3;

                // Supporting evidence
                pdf.setFontSize(8);
                pdf.setFont("helvetica", "bold");
                tc(...C.s300);

                pdf.text(
                    "SUPPORTING EVIDENCE",
                    M + 4,
                    y
                );

                y += 6;

                pdf.setFontSize(7.5);
                pdf.setFont("helvetica", "normal");
                tc(...C.s400);

                const supportingEvidence = [];

                if (aiVerdict === "PHISHING") {
                    supportingEvidence.push(
                        `AI models produced ${phishingPct}% phishing probability.`
                    );
                } else if (aiVerdict === "LEGITIMATE") {
                    supportingEvidence.push(
                        `AI models produced ${legitimatePct}% legitimate probability.`
                    );
                }

                if (senderTrusted) {
                    supportingEvidence.push(
                        "Sender domain was verified as a trusted domain."
                    );

                    supportingEvidence.push(
                        "SPF, DKIM and DMARC authentication passed."
                    );
                } else {
                    supportingEvidence.push(
                        "Sender was not verified as a trusted brand sender."
                    );
                }

                if (supportingEvidence.length === 0) {
                    supportingEvidence.push(
                        "Manual verification of the email evidence is recommended."
                    );
                }

                supportingEvidence.forEach(item => {

                    checkY(7);

                    const lines = pdf.splitTextToSize(
                        "• " + item,
                        IW - 12
                    );

                    lines.forEach(line => {

                        pdf.text(
                            line,
                            M + 6,
                            y
                        );

                        y += 4.5;
                    });

                    y += 1;
                });
            });

            // Flags
            const flags = report.flags || [];
            if (flags.length) {
                section(`DETECTION FLAGS  (${flags.length})`, () => {
                    flags.forEach(f => {
                        checkY(7);
                        const warn = f.includes("fail")||f.includes("FAIL")||f.includes("⚠");
                        pdf.setFontSize(7.5); pdf.setFont("helvetica","normal");
                        tc(...(warn ? C.red : C.s300));
                        pdf.text(`• ${f}`, M+4, y, {maxWidth: IW-8}); y += 6;
                    });
                });
            }

            // SHAP
            const shap = report.explainability?.top_features || [];
            if (shap.length) {
                section("SHAP EXPLAINABILITY — WHY THIS VERDICT?", () => {
                    pdf.setFontSize(7.5); pdf.setFont("helvetica","normal");
                    tc(...C.s400);
                    pdf.text(`Base score: ${report.explainability?.base_value?.toFixed(4)||"—"}   |   Red = phishing push   |   Green = legitimate push`, M+4, y);
                    y += 7;

                    const maxV = Math.max(...shap.map(s => Math.abs(s.shap_value)));
                    shap.slice(0,8).forEach(f => {
                        checkY(8);
                        const bW    = 55;
                        const fillW = maxV > 0 ? (Math.abs(f.shap_value)/maxV)*bW : 0;
                        const bColor= f.direction === "phishing" ? C.red : C.green;

                        pdf.setFontSize(7); pdf.setFont("helvetica","bold");
                        tc(...C.s300); pdf.text(f.feature, M+4, y);

                        fc(50,65,85); pdf.rect(M+52, y-3.5, bW, 4, "F");
                        fc(...bColor); pdf.rect(M+52, y-3.5, fillW, 4, "F");

                        pdf.setFont("helvetica","normal");
                        tc(...bColor);
                        pdf.text(`${f.shap_value>=0?"+":""}${f.shap_value.toFixed(4)}`, M+112, y);
                        tc(...C.s500); pdf.text(f.direction, M+138, y);
                        y += 7;
                    });
                });
            }

            // ════════════════════════════════════════════════════════════════
            // PAGE 2
            // ════════════════════════════════════════════════════════════════
            newPage();

            // Intent
            const intent = report.nlp_extra?.intent;
            if (intent) {
                section("INTENT CLASSIFICATION", () => {
                    kv("Top Intent",  intent.top_intent  || "—");
                    kv("Confidence", `${((intent.confidence||0)*100).toFixed(1)}%`);
                    y += 2;
                    (intent.all_intents||[]).forEach(i => {
                        checkY(7);
                        const pct = (i.score*100).toFixed(1);
                        const isTop = i.label === intent.top_intent;
                        pdf.setFontSize(7); pdf.setFont("helvetica", isTop?"bold":"normal");
                        tc(...(isTop ? C.white : C.s400));
                        pdf.text(i.label, M+4, y);
                        fc(...(isTop ? C.indigo : C.card));
                        pdf.roundedRect(M+70, y-3.5, (IW-76)*(i.score), 4, 1,1,"F");
                        tc(...C.s400); pdf.text(`${pct}%`, W-M-4, y, {align:"right"});
                        y += 6;
                    });
                });
            }

            // GeoIP
            const geo = report.geoip || {};
            if (geo.originating_ip) {
                section("GEOIP — EMAIL ORIGIN", () => {
                    const loc = geo.location || {};
                    const riskColor = geo.high_risk_country ? C.red : C.green;
                    kv("Originating IP",  geo.originating_ip || "—");
                    kv("Country",  `${loc.country||"—"}${geo.high_risk_country?" ⚠ HIGH RISK":""}`, riskColor);
                    kv("Region / City",   `${loc.region||"—"} / ${loc.city||"—"}`);
                    kv("ISP",             geo.isp || "—");
                    kv("Organization",    geo.org || "—");
                    kv("Coordinates",     loc.lat&&loc.lon ? `${loc.lat}, ${loc.lon}` : "—");
                    if (loc.lat && loc.lon) {
                        y += 2;
                        const mUrl = `https://www.google.com/maps?q=${loc.lat},${loc.lon}`;
                        pdf.setFontSize(7.5); tc(...C.indigo);
                        pdf.textWithLink(`🗺 View on Google Maps → ${mUrl}`, M+4, y, {url: mUrl});
                        y += 6;
                    }
                });
            }

            // Forensics
            const fo = report.forensics || {};
            section("FORENSICS ANALYSIS", () => {
                const fsecs = [
                    ["Auth Headers",      fo.auth_headers?.verdict,     fo.auth_headers?.findings],
                    ["Address Mismatch",  fo.address_mismatch?.verdict, fo.address_mismatch?.findings],
                    ["Typosquatting",     fo.typosquat?.verdict,        fo.typosquat?.findings],
                    ["WHOIS / Domain Age",fo.whois?.verdict,            fo.whois?.domains],
                    ["URL Reputation",    fo.url_reputation?.verdict,   fo.url_reputation?.findings],
                ];
                fsecs.forEach(([title, verd, findings]) => {
                    checkY(10);
                    const vc = verd==="high"||verd==="fail" ? C.red
                            : verd==="medium"              ? C.yellow
                            : verd==="trusted"||verd==="pass" ? C.green
                            : C.s500;
                    pdf.setFontSize(8); pdf.setFont("helvetica","bold");
                    tc(...C.s300); pdf.text(title, M+4, y);
                    tc(...vc); pdf.text((verd||"—").toUpperCase(), W-M-4, y, {align:"right"});
                    y += 5;
                    (findings||[]).slice(0,2).forEach(fi => {
                        const detail = fi.meaning||fi.reasons?.join(", ")||fi.registrar||"";
                        if (detail) {
                            checkY(6);
                            pdf.setFontSize(7); pdf.setFont("helvetica","normal");
                            tc(...C.s500);
                            pdf.text(`  → ${detail.slice(0,88)}`, M+4, y, {maxWidth: IW-8});
                            y += 5;
                        }
                    });
                    y += 2;
                });
            });

            // SMTP
            const smtp = report.smtp_chain || {};
            section("SMTP CHAIN TRAVERSAL", () => {
                const sc = smtp.chain_suspicious ? C.yellow : C.green;
                kv("Hop Count",     smtp.hop_count ?? "—");
                kv("Originating IP",smtp.originating_ip || "—");
                kv("Chain Status",  smtp.chain_suspicious ? "⚠ SUSPICIOUS" : "✓ CLEAN", sc);
                (smtp.anomalies||[]).forEach(a => {
                    checkY(6); tc(...C.yellow);
                    pdf.setFontSize(7); pdf.setFont("helvetica","normal");
                    pdf.text(`⚠ ${a}`, M+4, y, {maxWidth: IW-8}); y += 5;
                });
                const fcrdns = smtp.fcrdns_results || [];
                if (fcrdns.length) {
                    y += 2;
                    pdf.setFontSize(7.5); pdf.setFont("helvetica","bold");
                    tc(...C.s400); pdf.text("FCrDNS Results:", M+4, y); y += 5;
                    fcrdns.forEach(r => {
                        checkY(5);
                        const fc_ = r.fcrdns_pass===true  ? C.green
                                : r.fcrdns_pass===false  ? C.red
                                : C.s500;
                        const st  = r.fcrdns_pass===true  ? "✓ PASS"
                                : r.fcrdns_pass===false  ? "✗ FAIL" : "? Unknown";
                        pdf.setFont("helvetica","normal"); pdf.setFontSize(7);
                        tc(...C.s400); pdf.text(r.ip, M+8, y);
                        tc(...fc_);   pdf.text(st, M+55, y);
                        tc(...C.s500);pdf.text(r.rdns_hostname||"", M+80, y);
                        y += 5;
                    });
                }
            });

            // ════════════════════════════════════════════════════════════════
            // PAGE 3 — Blockchain + Seal
            // ════════════════════════════════════════════════════════════════
            newPage();

            section("BLOCKCHAIN FORENSIC ANCHOR", () => {
                const bRows = [
                    ["Analysis ID",  bc.analysis_id  || "—",          null],
                    ["SHA-256 Hash", bc.report_hash  || "—",          null],
                    ["IPFS CID",     bc.ipfs_cid     || "Pending...", null],
                    ["TX Hash",      bc.tx_hash      || "Pending...", null],
                    ["Network",      "Ethereum Sepolia Testnet",      null],
                    ["Status",       bc.tx_hash ? "✓ ANCHORED" : "⏳ ANCHORING",
                                    bc.tx_hash ? C.green : C.yellow],
                ];
                bRows.forEach(([lbl, val, col]) => kv(lbl, val, col||undefined));

                if (bc.polygonscan_url) {
                    y += 2; tc(...C.indigo); pdf.setFontSize(7.5);
                    pdf.textWithLink(`🔗 Verify on Etherscan → ${bc.polygonscan_url}`,
                        M+4, y, {url: bc.polygonscan_url}); y += 6;
                }
                if (bc.ipfs_cid) {
                    const ipfsUrl = `https://gateway.pinata.cloud/ipfs/${bc.ipfs_cid}`;
                    tc(...C.indigo); pdf.setFontSize(7.5);
                    pdf.textWithLink(`📦 IPFS Report → ${ipfsUrl}`, M+4, y, {url: ipfsUrl});
                    y += 6;
                }
                y += 3;
                pdf.setFontSize(7); pdf.setFont("helvetica","bold");
                tc(...C.s400); pdf.text("Legal Compliance:", M+4, y); y += 5;
                (bc.law_reference||[]).forEach(law => {
                    checkY(5); pdf.setFont("helvetica","normal");
                    tc(...C.s500); pdf.text(`• ${law}`, M+4, y); y += 5;
                });
            });

            // Verification guide
            section("HOW TO VERIFY TAMPER-PROOF INTEGRITY", () => {
                const steps = [
                    "1. Open the IPFS CID link above and download the JSON report",
                    "2. Compute SHA-256 hash of the downloaded file (use any SHA-256 tool)",
                    "3. Compare it to the SHA-256 Hash shown in this report (same value is on-chain)",
                    "4. If hashes match — report was never modified after analysis ✓",
                    "5. The blockchain record is permanent and publicly verifiable by anyone",
                ];
                steps.forEach(s => {
                    checkY(6); pdf.setFontSize(7.5); pdf.setFont("helvetica","normal");
                    tc(...C.s300); pdf.text(s, M+4, y, {maxWidth: IW-8}); y += 6;
                });
            });

            // ── SEAL ──────────────────────────────────────────────────────────
            checkY(80); y += 8;
            const cx = W/2;
            const cy = y + 24;

            dc(...C.indigo); pdf.setLineWidth(1.5);
            pdf.circle(cx, cy, 24, "S");
            dc(...C.indigo); pdf.setLineWidth(0.4);
            pdf.circle(cx, cy, 20, "S");
            pdf.circle(cx, cy, 14, "S");

            tc(...C.indigo);
            pdf.setFontSize(7);   pdf.setFont("helvetica","bold");
            pdf.text("EMAILGUARD AI", cx, cy-6,  {align:"center"});
            pdf.setFontSize(6);   pdf.setFont("helvetica","normal");
            pdf.text("FORENSIC SEAL",  cx, cy-1,  {align:"center"});
            pdf.text("SIH 2026",       cx, cy+4,  {align:"center"});
            pdf.setFontSize(5);
            pdf.text("BLOCKCHAIN VERIFIED", cx, cy+9, {align:"center"});

            // Signature lines
            dc(...C.s500); pdf.setLineWidth(0.3);
            pdf.line(M+10, cy+40, M+70, cy+40);
            pdf.line(W-M-70, cy+40, W-M-10, cy+40);
            tc(...C.s400); pdf.setFontSize(7); pdf.setFont("helvetica","normal");
            pdf.text("Authorized Signature", M+40, cy+45, {align:"center"});
            pdf.text("System Generated",     W-M-40, cy+45, {align:"center"});
            tc(...C.s500); pdf.setFontSize(6);
            pdf.text("Auto-generated by EmailGuard AI. Verify authenticity via blockchain anchor above.", cx, cy+53, {align:"center"});
            if (bc.report_hash) {
                pdf.text(`Hash: ${bc.report_hash.slice(0,40)}...`, cx, cy+59, {align:"center"});
            }

            y = cy + 65;

            // Footer on last page
            addFooter();

            // ── Save ──────────────────────────────────────────────────────────
            const fname = `EmailGuard-${verdict}-${bc.analysis_id?.slice(0,8)||Date.now()}.pdf`;
            pdf.save(fname);
            Utils.toast("✅ PDF downloaded successfully!", "success");

        } catch (err) {
            console.error("PDF error:", err);
            Utils.toast("PDF generation failed: " + err.message, "error");
        }
    },
    }