// js/api.js
// ── All backend fetch calls ───────────────────────────────────────────────

const API = {

    base: () => CONFIG.BACKEND_URL,

    // Analyze email — returns full report JSON
    async analyzeEmail(file, onProgress) {
        const formData = new FormData();
        formData.append("file", file);

        if (onProgress) onProgress("Uploading email...", 10);

        const res = await fetch(`${this.base()}/analyze`, {
            method: "POST",
            body:   formData,
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${res.status}`);
        }

        if (onProgress) onProgress("Processing complete", 100);
        return await res.json();
    },

    // Get saved analysis by ID
    async getAnalysis(analysisId) {
        const res = await fetch(`${this.base()}/analysis/${analysisId}`);
        if (!res.ok) throw new Error(`Analysis not found: ${res.status}`);
        return await res.json();
    },

    // Verify on blockchain
    async verifyOnChain(analysisId) {
        const res = await fetch(`${this.base()}/verify/${analysisId}`);
        if (!res.ok) throw new Error(`Verification failed: ${res.status}`);
        return await res.json();
    },

    // Health check
    async health() {
        const res = await fetch(`${this.base()}/health`);
        return await res.json();
    },
};