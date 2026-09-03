// js/dashboard.js
// ── Dashboard — analyses table, stats, chart, live GeoIP map ─────────────

const { createClient } = supabase;
const _db = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY);

const DashboardController = {

    allRows:      [],
    filtered:     [],
    page:         1,
    perPage:      10,
    role:         null,
    verdictChart: null,
    map:          null,
    markers:      [],

    async init() {
        this.role = Utils.getUserRole();
        this.updateSubtitle();
        this.showExportBtn();
        this.initMap();
        await this.loadAnalyses();
    },

    updateSubtitle() {
        const el = document.getElementById("dashboard-subtitle");
        if (!el) return;
        const map = {
            [CONFIG.ROLES.USER]:  "Your personal analysis history (last 10)",
            [CONFIG.ROLES.ORG]:   "All analyses across your organization",
            [CONFIG.ROLES.CYBER]: "Your analysis history with full forensic access",
        };
        el.textContent = map[this.role] || "";
    },

    showExportBtn() {
        if (this.role === CONFIG.ROLES.ORG) {
            document.getElementById("export-csv-btn")?.classList.remove("hidden");
        }
    },

    // ── Map init ──────────────────────────────────────────────────────────
    initMap() {
        const mapEl = document.getElementById("dashboard-map");
        if (!mapEl || this.map) return;

        // Dark tile layer
        this.map = L.map("dashboard-map", {
            zoomControl:        true,
            scrollWheelZoom:    true,
            dragging:           true,       // ← explicit
            attributionControl: false,
        }).setView([20, 0], 2);

        // Dark map tiles
        L.tileLayer(
            "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
            { maxZoom: 18 }
        ).addTo(this.map);

        // Attribution
        L.control.attribution({ prefix: false })
            .addAttribution("© OpenStreetMap © CARTO")
            .addTo(this.map);

    },

    // ── Plot all GeoIP pins ───────────────────────────────────────────────
    plotMapPins(rows) {
        if (!this.map) return;

        // Clear existing markers
        this.markers.forEach(m => this.map.removeLayer(m));
        this.markers = [];

        const validRows = rows.filter(r =>
            r.report_json?.geoip?.location?.lat &&
            r.report_json?.geoip?.location?.lon
        );

        if (!validRows.length) {
            document.getElementById("map-summary").textContent =
                "No GeoIP data available yet — analyze some emails first.";
            return;
        }

        const bounds = [];

        validRows.forEach(row => {
            const geo     = row.report_json.geoip;
            const loc     = geo.location;
            const verdict = row.final_verdict || "UNKNOWN";
            const lat     = loc.lat;
            const lon     = loc.lon;

            // Color by verdict
            const color = verdict === "PHISHING"   ? "#ef4444"
                        : verdict === "LEGITIMATE"  ? "#22c55e"
                        : verdict === "HITL_QUEUE"  ? "#f59e0b"
                        : "#94a3b8";

            // Pulse effect for phishing
            const isPulsing = verdict === "PHISHING";

            // Custom marker
            const markerHtml = `
            <div style="
                width: 16px; height: 16px;
                background: ${color};
                border: 2px solid white;
                border-radius: 50%;
                box-shadow: 0 0 ${isPulsing ? "8px 3px" : "4px 1px"} ${color};
                ${isPulsing ? "animation: pulse 1.5s infinite;" : ""}
                cursor: pointer;
            "></div>`;

            const icon = L.divIcon({
                html:        markerHtml,
                className:   "",
                iconSize:    [16, 16],
                iconAnchor:  [8, 8],
                popupAnchor: [0, -12],
            });

            const marker = L.marker([lat, lon], { icon });

            // Popup content
            const filename = Utils.truncate(row.source_filename || "unknown", 25);
            const date     = Utils.formatDate(row.created_at);
            const mapsUrl  = `https://www.google.com/maps?q=${lat},${lon}`;
            const score    = row.fused_score !== null && row.fused_score !== undefined
                           ? (row.fused_score * 100).toFixed(1) + "%" : "—";

            const verdictColor = verdict === "PHISHING"  ? "#ef4444"
                               : verdict === "LEGITIMATE" ? "#22c55e"
                               : "#f59e0b";

            marker.bindPopup(`
            <div style="
                background: #1e293b;
                color: #f1f5f9;
                border-radius: 10px;
                padding: 12px;
                min-width: 200px;
                font-family: system-ui, sans-serif;
                border: 1px solid #334155;
            ">
                <div style="
                    background: ${verdictColor}22;
                    border: 1px solid ${verdictColor};
                    color: ${verdictColor};
                    font-weight: bold;
                    font-size: 12px;
                    padding: 4px 8px;
                    border-radius: 6px;
                    text-align: center;
                    margin-bottom: 10px;
                ">${verdict}</div>

                <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;">
                    📄 ${filename}
                </div>
                <div style="font-size: 11px; color: #94a3b8; margin-bottom: 2px;">
                    🌐 ${geo.originating_ip || "—"}
                </div>
                <div style="font-size: 11px; color: #94a3b8; margin-bottom: 2px;">
                    📍 ${loc.city || "—"}, ${loc.country || "—"}
                </div>
                <div style="font-size: 11px; color: #94a3b8; margin-bottom: 2px;">
                    🏢 ${geo.isp || "—"}
                </div>
                <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">
                    📊 Confidence: ${score}
                </div>
                <div style="font-size: 10px; color: #64748b; margin-bottom: 8px;">
                    🕒 ${date}
                </div>

                <div style="display: flex; gap: 6px; flex-direction: column;">
                    <a href="${mapsUrl}" target="_blank" style="
                        display: block;
                        background: #4f46e5;
                        color: white;
                        text-align: center;
                        padding: 6px 10px;
                        border-radius: 6px;
                        font-size: 11px;
                        font-weight: 600;
                        text-decoration: none;
                    ">🗺 Open in Google Maps</a>

                    <button onclick="DashboardController.openReportFromMap('${row.id}')" style="
                        background: #1e293b;
                        color: #818cf8;
                        border: 1px solid #4f46e5;
                        width: 100%;
                        padding: 6px 10px;
                        border-radius: 6px;
                        font-size: 11px;
                        font-weight: 600;
                        cursor: pointer;
                    ">📋 View Full Report</button>
                </div>

                ${geo.high_risk_country ? `
                <div style="
                    margin-top: 8px;
                    background: #ef444420;
                    border: 1px solid #ef4444;
                    color: #fca5a5;
                    padding: 4px 8px;
                    border-radius: 6px;
                    font-size: 10px;
                    text-align: center;
                ">⚠️ High-Risk Country</div>` : ""}
            </div>`, {
                maxWidth:   260,
                className:  "dark-popup",
            });

            marker.addTo(this.map);
            this.markers.push(marker);
            bounds.push([lat, lon]);
        });

        // Fit map to show all pins
        if (bounds.length > 0) {
            this.map.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 });
        }

        // Summary
        const phishingPins = validRows.filter(r => r.final_verdict === "PHISHING").length;
        const countries    = [...new Set(validRows.map(r =>
            r.report_json?.geoip?.location?.country).filter(Boolean))];

        document.getElementById("map-summary").textContent =
            `${validRows.length} email origin${validRows.length !== 1 ? "s" : ""} plotted` +
            (phishingPins ? ` • ${phishingPins} phishing` : "") +
            (countries.length ? ` • Countries: ${countries.slice(0, 5).join(", ")}${countries.length > 5 ? "..." : ""}` : "");
    },

    // ── Open report from map popup ────────────────────────────────────────
    async openReportFromMap(analysisId) {
        this.map.closePopup();
        await this.openReport(analysisId);
    },

    // ── Load analyses from Supabase ───────────────────────────────────────
    async loadAnalyses() {
        try {
            let query = _db
                .from("analyses")
                .select("id, created_at, source_filename, final_verdict, fused_score, blockchain_anchored, tx_hash, ipfs_cid, report_json")
                .order("created_at", { ascending: false });

            if (this.role !== CONFIG.ROLES.ORG) {
                const user = JSON.parse(localStorage.getItem("sb_user") || "{}");
                query = query.eq("user_id", user.id);
                if (this.role === CONFIG.ROLES.USER) {
                    query = query.limit(10);
                }
            }

            const { data, error } = await query;
            if (error) throw error;

            this.allRows  = data || [];
            this.filtered = [...this.allRows];
            this.page     = 1;

            this.renderStats();
            this.renderChart();
            this.renderTable();
            this.plotMapPins(this.allRows);   // ← plot all pins

        } catch (err) {
            document.getElementById("table-loading").innerHTML = `
                <p class="text-red-400 text-sm px-6 py-8">Failed to load: ${err.message}</p>`;
        }
    },

    // ── Stats ─────────────────────────────────────────────────────────────
    renderStats() {
        const rows     = this.allRows;
        const total    = rows.length;
        const phishing = rows.filter(r => r.final_verdict === "PHISHING").length;
        const legit    = rows.filter(r => r.final_verdict === "LEGITIMATE").length;
        const hitl     = rows.filter(r => r.final_verdict === "HITL_QUEUE").length;
        const anchored = rows.filter(r => r.blockchain_anchored).length;
        const pending  = total - anchored;

        document.getElementById("stat-total").textContent    = total;
        document.getElementById("stat-phishing").textContent = phishing;
        document.getElementById("stat-legit").textContent    = legit;
        document.getElementById("stat-hitl").textContent     = hitl;
        document.getElementById("stat-anchored").textContent = anchored;
        document.getElementById("stat-pending").textContent  = pending;
    },

    // ── Donut chart ───────────────────────────────────────────────────────
    renderChart() {
        const rows     = this.allRows;
        const phishing = rows.filter(r => r.final_verdict === "PHISHING").length;
        const legit    = rows.filter(r => r.final_verdict === "LEGITIMATE").length;
        const hitl     = rows.filter(r => r.final_verdict === "HITL_QUEUE").length;

        const canvas = document.getElementById("verdict-chart");
        if (!canvas) return;

        if (this.verdictChart) this.verdictChart.destroy();

        this.verdictChart = new Chart(canvas, {
            type: "doughnut",
            data: {
                labels:   ["Phishing", "Legitimate", "Needs Review"],
                datasets: [{
                    data:            [phishing, legit, hitl],
                    backgroundColor: [
                        "rgba(239,68,68,0.8)",
                        "rgba(34,197,94,0.8)",
                        "rgba(245,158,11,0.8)",
                    ],
                    borderColor: "rgba(15,23,42,1)",
                    borderWidth: 3,
                }]
            },
            options: {
                responsive:          true,
                maintainAspectRatio: false,
                cutout: "70%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color:  "#94a3b8",
                            font:   { size: 11 },
                            padding: 12,
                        }
                    }
                }
            }
        });
    },

    // ── Filter ────────────────────────────────────────────────────────────
    applyFilter() {
        const val     = document.getElementById("verdict-filter").value;
        this.filtered = val === "all"
            ? [...this.allRows]
            : this.allRows.filter(r => r.final_verdict === val);
        this.page = 1;
        this.renderTable();

        // Update map to show only filtered pins
        this.plotMapPins(this.filtered);
    },

    // ── Table ─────────────────────────────────────────────────────────────
    renderTable() {
        const loading    = document.getElementById("table-loading");
        const empty      = document.getElementById("table-empty");
        const container  = document.getElementById("table-container");
        const pagination = document.getElementById("pagination");

        loading.classList.add("hidden");

        if (!this.filtered.length) {
            empty.classList.remove("hidden");
            container.classList.add("hidden");
            pagination.classList.add("hidden");
            return;
        }

        empty.classList.add("hidden");
        container.classList.remove("hidden");

        const start = (this.page - 1) * this.perPage;
        const end   = start + this.perPage;
        const page  = this.filtered.slice(start, end);

        const tbody = document.getElementById("analyses-table-body");
        tbody.innerHTML = page.map(row => {
            const verdict  = row.final_verdict || "UNKNOWN";
            const txtCls   = Utils.verdictColor(verdict);
            const score    = row.fused_score !== null && row.fused_score !== undefined
                           ? (row.fused_score * 100).toFixed(1) + "%" : "—";
            const anchored = row.blockchain_anchored;
            const geo      = row.report_json?.geoip;
            const loc      = geo?.location;
            const hasGeo   = loc?.lat && loc?.lon;
            const mapsUrl  = hasGeo
                           ? `https://www.google.com/maps?q=${loc.lat},${loc.lon}`
                           : null;

            const chainBadge = anchored
                ? `<span class="text-green-400 text-xs">✓ Anchored</span>`
                : `<span class="text-yellow-400 text-xs animate-pulse">⏳ Pending</span>`;

            const geoCell = hasGeo ? `
            <a href="${mapsUrl}" target="_blank"
                class="flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 transition group"
                title="Open in Google Maps">
                <span class="w-2 h-2 rounded-full flex-shrink-0 ${
                    verdict === "PHISHING"  ? "bg-red-500" :
                    verdict === "LEGITIMATE"? "bg-green-500" : "bg-yellow-400"
                }"></span>
                <span>${loc.city || "—"}, ${loc.country || "—"}</span>
                <span class="opacity-0 group-hover:opacity-100 transition text-slate-500">↗</span>
            </a>` : `<span class="text-slate-600 text-xs">No GeoIP</span>`;

            return `
            <tr class="border-b border-slate-800/50 hover:bg-slate-800/30 transition">
                <td class="px-6 py-4 cursor-pointer" onclick="DashboardController.openReport('${row.id}')">
                    <div class="flex items-center gap-2">
                        <span class="text-slate-400">📄</span>
                        <span class="text-slate-200 text-sm"
                              title="${row.source_filename}">
                            ${Utils.truncate(row.source_filename || "unknown", 28)}
                        </span>
                    </div>
                </td>
                <td class="px-6 py-4">
                    <span class="${txtCls} font-bold text-sm">${verdict}</span>
                </td>
                <td class="px-6 py-4">
                    <span class="text-slate-300 font-mono text-sm">${score}</span>
                </td>
                <td class="px-6 py-4">${chainBadge}</td>
                <td class="px-6 py-4">${geoCell}</td>
                <td class="px-6 py-4">
                    <span class="text-slate-400 text-xs">${Utils.formatDate(row.created_at)}</span>
                </td>
                <td class="px-6 py-4">
                    <button onclick="DashboardController.openReport('${row.id}')"
                        class="text-indigo-400 hover:text-indigo-300 text-xs transition">
                        View →
                    </button>
                </td>
            </tr>`;
        }).join("");

        // Pagination
        const totalPages = Math.ceil(this.filtered.length / this.perPage);
        if (totalPages > 1) {
            pagination.classList.remove("hidden");
            document.getElementById("pagination-info").textContent =
                `Showing ${start + 1}–${Math.min(end, this.filtered.length)} of ${this.filtered.length}`;
            document.getElementById("prev-btn").disabled = this.page <= 1;
            document.getElementById("next-btn").disabled = this.page >= totalPages;
        } else {
            pagination.classList.add("hidden");
        }
    },

    prevPage() {
        if (this.page > 1) { this.page--; this.renderTable(); }
    },

    nextPage() {
        const totalPages = Math.ceil(this.filtered.length / this.perPage);
        if (this.page < totalPages) { this.page++; this.renderTable(); }
    },

    // ── Open report ───────────────────────────────────────────────────────
    async openReport(analysisId) {
        try {
            Utils.toast("Loading report...", "info");
            const row = await API.getAnalysis(analysisId);
            if (row?.report_json) {
                const report = row.report_json;
                if (report.blockchain) {
                    report.blockchain.ipfs_cid        = row.ipfs_cid  || report.blockchain.ipfs_cid;
                    report.blockchain.tx_hash         = row.tx_hash   || report.blockchain.tx_hash;
                    report.blockchain.polygonscan_url = row.tx_hash
                        ? `https://sepolia.etherscan.io/tx/${row.tx_hash}`
                        : report.blockchain.polygonscan_url;
                    report.blockchain.status = row.blockchain_anchored ? "anchored" : "anchoring";
                }
                Utils.saveReportToSession(report);
                window.location.href = "report.html";
            }
        } catch (err) {
            Utils.toast("Failed to load report: " + err.message, "error");
        }
    },

    async openReportFromMap(analysisId) {
        this.map?.closePopup();
        await this.openReport(analysisId);
    },

    // ── CSV Export (Org only) ─────────────────────────────────────────────
    exportCSV() {
        if (this.role !== CONFIG.ROLES.ORG) return;
        const rows = this.filtered;
        if (!rows.length) { Utils.toast("No data to export", "warning"); return; }

        const headers = [
            "ID", "Filename", "Verdict", "Fused Score",
            "Country", "City", "Originating IP",
            "Blockchain Anchored", "TX Hash", "Date"
        ];
        const lines = rows.map(r => {
            const geo = r.report_json?.geoip || {};
            const loc = geo.location || {};
            return [
                r.id,
                `"${r.source_filename || ""}"`,
                r.final_verdict || "",
                r.fused_score?.toFixed(4) || "",
                loc.country || "",
                loc.city    || "",
                geo.originating_ip || "",
                r.blockchain_anchored ? "Yes" : "No",
                r.tx_hash || "",
                r.created_at || "",
            ].join(",");
        });

        const csv  = [headers.join(","), ...lines].join("\n");
        const blob = new Blob([csv], { type: "text/csv" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href     = url;
        a.download = `emailguard-analyses-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        Utils.toast("CSV exported!", "success");
    },
};