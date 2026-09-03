// js/auth.js
// ── Supabase auth — login, signup, logout, session ────────────────────────

const { createClient } = supabase;
const _supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY);

const Auth = {

    // Sign up new user
    async signup(email, password, role, orgName = "") {
        const { data, error } = await _supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    role:     role,
                    org_name: orgName || "",
                }
            }
        });
        if (error) throw error;
        return data;
    },

    // Log in
    async login(email, password) {
        const { data, error } = await _supabase.auth.signInWithPassword({
            email,
            password,
        });
        if (error) throw error;
        // Persist session + user to localStorage
        localStorage.setItem("sb_session", JSON.stringify(data.session));
        localStorage.setItem("sb_user",    JSON.stringify(data.user));
        return data;
    },

    // Log out
    async logout() {
        await _supabase.auth.signOut();
        localStorage.removeItem("sb_session");
        localStorage.removeItem("sb_user");
        window.location.href = "index.html";
    },

    // Check if logged in
    isLoggedIn() {
        const session = localStorage.getItem("sb_session");
        if (!session) return false;
        try {
            const s = JSON.parse(session);
            // Check token expiry
            if (s.expires_at && Date.now() / 1000 > s.expires_at) {
                this.logout();
                return false;
            }
            return true;
        } catch { return false; }
    },

    // Get role
    getRole() {
        return Utils.getUserRole();
    },

    // Get access token for API calls
    getToken() {
        const raw = localStorage.getItem("sb_session");
        if (!raw) return null;
        try { return JSON.parse(raw)?.access_token || null; }
        catch { return null; }
    },

    // Update navbar based on auth state
    updateNavbar() {
        const loggedIn   = this.isLoggedIn();
        const email      = Utils.getUserEmail();
        const role       = this.getRole();

        const guestNav   = document.getElementById("guest-nav");
        const authNav    = document.getElementById("auth-nav");
        const userEmail  = document.getElementById("user-email");
        const userRole   = document.getElementById("user-role");

        if (guestNav)  guestNav.style.display  = loggedIn ? "none" : "flex";
        if (authNav)   authNav.style.display   = loggedIn ? "flex" : "none";
        if (userEmail) userEmail.textContent   = email || "";
        if (userRole)  userRole.textContent    = role ? role.toUpperCase() : "";
    },
};