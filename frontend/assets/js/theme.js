// assets/js/theme.js
const STORAGE_KEY = "nt.theme";

function getPreferredTheme() {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;

    const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)")?.matches;
    return prefersDark ? "dark" : "light";
}

function setTheme(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
}

function updateToggleIcon(btn, theme) {
    if (!btn) return;
    btn.innerHTML = theme === "dark"
        ? '<i class="bi bi-sun"></i>'
        : '<i class="bi bi-moon-stars"></i>';
}

document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("themeToggle");
    const theme = getPreferredTheme();

    setTheme(theme);
    updateToggleIcon(btn, theme);

    btn?.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-bs-theme") || "light";
        const next = current === "dark" ? "light" : "dark";
        localStorage.setItem(STORAGE_KEY, next);
        setTheme(next);
        updateToggleIcon(btn, next);
    });

    // If user has NOT explicitly chosen, follow OS changes
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", () => {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) return;
        const next = getPreferredTheme();
        setTheme(next);
        updateToggleIcon(btn, next);
    });
});
