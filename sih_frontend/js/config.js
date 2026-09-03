// js/config.js
// ── Single source of truth for all URLs and keys ──────────────────────────
// To go live: change BACKEND_URL to your ngrok URL. Nothing else changes.

const CONFIG = {
    BACKEND_URL: "https://thouseef68--emailguard-api-web.modal.run",
    SUPABASE_URL:      "https://sarmwmdqgkappmekzlmp.supabase.co",
    SUPABASE_ANON_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNhcm13bWRxZ2thcHBtZWt6bG1wIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODgyNjI4MjksImV4cCI6MjEwMzgzODgyOX0.u6Jxwy2kGs34hBQM_gX8_Wb9YH78nx7KFP9K_Mumh7A",         // anon/public key — safe to expose
    APP_NAME:          "EmailGuard AI",
    VERSION:           "2.0.0",
    ROLES: {
        USER:  "user",
        ORG:   "org",
        CYBER: "cyber",
    },
};