// js/analyze.js
// ── Upload, progress animation, analysis trigger ──────────────────────────

let selectedFile = null;

const ANALYSIS_STEPS = [
    { label: "Parsing email structure",           pct: 10 },
    { label: "Running DeBERTa V12 (AI model)",    pct: 25 },
    { label: "Running XGBoost V3 (structural)",   pct: 40 },
    { label: "Fusion Gate decision",              pct: 50 },
    { label: "Forensics — SPF/DKIM/DMARC/WHOIS", pct: 60 },
    { label: "GeoIP origin lookup",               pct: 68 },
    { label: "SHAP explainability",               pct: 74 },
    { label: "Zero-shot intent classification",   pct: 80 },
    { label: "Vision — OCR + QR + Logo",          pct: 85 },
    { label: "Attachment scan — PDF + Office",    pct: 90 },
    { label: "SMTP chain traversal + FCrDNS",     pct: 95 },
    { label: "Anchoring on Sepolia blockchain",   pct: 99 },
];

// ── Drag and drop handlers ────────────────────────────────────────────────

function handleDragOver(e) {
    e.preventDefault();
    document.getElementById("drop-zone").classList.add("border-indigo-500", "bg-indigo-500/5");
}

function handleDragLeave(e) {
    document.getElementById("drop-zone").classList.remove("border-indigo-500", "bg-indigo-500/5");
}

function handleDrop(e) {
    e.preventDefault();
    handleDragLeave(e);
    const file = e.dataTransfer.files[0];
    if (file) setFile(file);
}

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) setFile(file);
}

function setFile(file) {
    selectedFile = file;

    // Show preview
    document.getElementById("file-name").textContent = file.name;
    document.getElementById("file-size").textContent = `${(file.size / 1024).toFixed(1)} KB`;
    document.getElementById("file-preview").classList.remove("hidden");

    // Enable analyze button
    document.getElementById("analyze-btn").disabled = false;
}

function clearFile() {
    selectedFile = null;
    document.getElementById("file-preview").classList.add("hidden");
    document.getElementById("analyze-btn").disabled = true;
    document.getElementById("file-input").value = "";
}

function resetPage() {
    document.getElementById("upload-section").classList.remove("hidden");
    document.getElementById("progress-section").classList.add("hidden");
    document.getElementById("error-section").classList.add("hidden");
    clearFile();
}

// ── Progress UI ────────────────────────────────────────────────────────────

function renderSteps() {
    const container = document.getElementById("progress-steps");
    container.innerHTML = ANALYSIS_STEPS.map((step, i) => `
        <div id="step-${i}" class="flex items-center gap-3 p-3 rounded-lg transition-all duration-300">
            <div id="step-icon-${i}" class="w-5 h-5 rounded-full border-2 border-slate-700 flex items-center justify-center text-xs flex-shrink-0">
                <span class="hidden">✓</span>
            </div>
            <span id="step-label-${i}" class="text-slate-500 text-sm">${step.label}</span>
        </div>
    `).join("");
}

function markStepActive(i) {
    const el   = document.getElementById(`step-${i}`);
    const icon = document.getElementById(`step-icon-${i}`);
    const lbl  = document.getElementById(`step-label-${i}`);
    if (!el) return;
    el.classList.add("bg-indigo-500/10");
    icon.className = "w-5 h-5 rounded-full border-2 border-indigo-500 flex items-center justify-center text-xs flex-shrink-0 animate-pulse";
    lbl.className  = "text-white text-sm font-medium";
}

function markStepDone(i) {
    const el   = document.getElementById(`step-${i}`);
    const icon = document.getElementById(`step-icon-${i}`);
    const lbl  = document.getElementById(`step-label-${i}`);
    if (!el) return;
    el.classList.remove("bg-indigo-500/10");
    el.classList.add("bg-green-500/5");
    icon.className  = "w-5 h-5 rounded-full bg-green-500 flex items-center justify-center text-xs flex-shrink-0";
    icon.innerHTML  = '<span class="text-white text-xs">✓</span>';
    lbl.className   = "text-slate-400 text-sm line-through";
}

function setProgress(pct) {
    document.getElementById("progress-bar").style.width = `${pct}%`;
    document.getElementById("progress-pct").textContent = `${pct}%`;
}

// ── Main analysis flow ─────────────────────────────────────────────────────

async function startAnalysis() {
    if (!selectedFile) return;

    // Switch views
    document.getElementById("upload-section").classList.add("hidden");
    document.getElementById("progress-section").classList.remove("hidden");
    document.getElementById("error-section").classList.add("hidden");

    renderSteps();
    setProgress(0);

    try {
        // Animate steps while waiting for backend
        let stepIdx = 0;
        markStepActive(0);

        const stepInterval = setInterval(() => {
            if (stepIdx < ANALYSIS_STEPS.length - 1) {
                markStepDone(stepIdx);
                stepIdx++;
                markStepActive(stepIdx);
                setProgress(ANALYSIS_STEPS[stepIdx].pct);
            }
        }, 1800);   // advance a step every 1.8s

        // Actual API call
        const report = await API.analyzeEmail(selectedFile);

        // Clear animation
        clearInterval(stepInterval);

        // Mark all done
        for (let i = 0; i <= stepIdx; i++) markStepDone(i);
        setProgress(100);

        // Wait a moment then redirect to report
        await new Promise(r => setTimeout(r, 600));

        Utils.saveReportToSession(report);
        window.location.href = "report.html";

    } catch (err) {
        document.getElementById("progress-section").classList.add("hidden");
        document.getElementById("error-section").classList.remove("hidden");
        document.getElementById("error-detail").textContent = err.message || "Unknown error occurred.";
    }
}