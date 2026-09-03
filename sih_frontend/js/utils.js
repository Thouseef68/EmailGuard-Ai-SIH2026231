// js/utils.js
// ── Shared helpers used by every other JS file ────────────────────────────

const Utils = {

    // Verdict → color class
    verdictColor(verdict) {
        if (!verdict) return "text-gray-400";
        const v = verdict.toUpperCase();
        if (v === "PHISHING")   return "text-red-500";
        if (v === "LEGITIMATE") return "text-green-500";
        if (v === "HITL_QUEUE") return "text-yellow-400";
        return "text-gray-400";
    },

    // Verdict → background color class
    verdictBg(verdict) {
        if (!verdict) return "bg-gray-700";
        const v = verdict.toUpperCase();
        if (v === "PHISHING")   return "bg-red-500/20 border border-red-500";
        if (v === "LEGITIMATE") return "bg-green-500/20 border border-green-500";
        if (v === "HITL_QUEUE") return "bg-yellow-400/20 border border-yellow-400";
        return "bg-gray-700";
    },

    // Verdict → emoji
    verdictIcon(verdict) {
        if (!verdict) return "❓";
        const v = verdict.toUpperCase();
        if (v === "PHISHING")   return "🚨";
        if (v === "LEGITIMATE") return "✅";
        if (v === "HITL_QUEUE") return "⚠️";
        return "❓";
    },

    // Probability → colored badge
    probBadge(prob) {
        if (prob === null || prob === undefined) return "—";
        const pct = (prob * 100).toFixed(1);
        const color = prob > 0.65 ? "text-red-400"
                    : prob < 0.40 ? "text-green-400"
                    : "text-yellow-400";
        return `<span class="${color} font-mono font-bold">${pct}%</span>`;
    },

    // SHAP direction → color
    shapColor(direction) {
        return direction === "phishing" ? "#ef4444" : "#22c55e";
    },

    // Format Unix timestamp
    formatTimestamp(unix) {
        if (!unix) return "—";
        return new Date(unix * 1000).toLocaleString("en-IN", {
            dateStyle: "medium",
            timeStyle: "short",
        });
    },

    // Format date string
    formatDate(str) {
        if (!str) return "—";
        return new Date(str).toLocaleString("en-IN", {
            dateStyle: "medium",
            timeStyle: "short",
        });
    },

    // Truncate long strings
    truncate(str, len = 40) {
        if (!str) return "—";
        return str.length > len ? str.slice(0, len) + "…" : str;
    },

    // Copy text to clipboard + show feedback
    async copyToClipboard(text, btnEl) {
        try {
            await navigator.clipboard.writeText(text);
            if (btnEl) {
                const original = btnEl.textContent;
                btnEl.textContent = "Copied!";
                setTimeout(() => { btnEl.textContent = original; }, 1500);
            }
        } catch {
            alert("Copy failed — please copy manually.");
        }
    },

    // Show toast notification
    toast(message, type = "info") {
        const colors = {
            info:    "bg-indigo-600",
            success: "bg-green-600",
            error:   "bg-red-600",
            warning: "bg-yellow-600",
        };
        const el = document.createElement("div");
        el.className = `fixed bottom-6 right-6 z-50 px-5 py-3 rounded-lg text-white
                        text-sm font-medium shadow-lg ${colors[type] || colors.info}
                        transition-opacity duration-500`;
        el.textContent = message;
        document.body.appendChild(el);
        setTimeout(() => { el.style.opacity = "0"; }, 2500);
        setTimeout(() => { el.remove(); }, 3000);
    },

    // Redirect if not logged in
    requireAuth() {
        const session = localStorage.getItem("sb_session");
        if (!session) {
            window.location.href = "login.html";
            return false;
        }
        return true;
    },

    // Get current user role
    getUserRole() {
        const raw = localStorage.getItem("sb_user");
        if (!raw) return null;
        try {
            const user = JSON.parse(raw);
            return user?.user_metadata?.role || CONFIG.ROLES.USER;
        } catch { return CONFIG.ROLES.USER; }
    },

    // Get current user email
    getUserEmail() {
        const raw = localStorage.getItem("sb_user");
        if (!raw) return null;
        try {
            return JSON.parse(raw)?.email || null;
        } catch { return null; }
    },

    // Save report to sessionStorage for report.html to read
    saveReportToSession(report) {
        sessionStorage.setItem("current_report", JSON.stringify(report));
    },

    // Load report from sessionStorage
    loadReportFromSession() {
        const raw = sessionStorage.getItem("current_report");
        if (!raw) return null;
        try { return JSON.parse(raw); } catch { return null; }
    },

    // Severity → badge html
    severityBadge(level) {
        const map = {
            high:    "bg-red-500/20 text-red-400 border border-red-500",
            medium:  "bg-yellow-500/20 text-yellow-400 border border-yellow-500",
            low:     "bg-green-500/20 text-green-400 border border-green-500",
            trusted: "bg-green-500/20 text-green-400 border border-green-500",
            none:    "bg-gray-700 text-gray-400",
        };
        const cls = map[level?.toLowerCase()] || map.none;
        return `<span class="px-2 py-0.5 rounded text-xs font-medium ${cls}">${level || "—"}</span>`;
    },
};