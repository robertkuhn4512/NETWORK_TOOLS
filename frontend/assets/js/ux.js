// assets/js/ux.js
document.addEventListener("DOMContentLoaded", () => {
    // Close sidebar offcanvas after clicking a nav link (mobile)
    document.querySelectorAll("#sidebar a.nav-link").forEach((a) => {
        a.addEventListener("click", () => {
            const ocEl = document.getElementById("sidebar");
            const oc = bootstrap.Offcanvas.getInstance(ocEl);
            if (oc) oc.hide();
        });
    });

    // Optional: enable tooltips if you add data-bs-toggle="tooltip"
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((el) => {
        bootstrap.Tooltip.getOrCreateInstance(el);
    });

    // Optional: auto-close topbar collapse on mobile when clicking a link
    document.querySelectorAll("#topbarNav .navbar-nav a.nav-link, #topbarNav .dropdown-menu a").forEach((a) => {
        a.addEventListener("click", () => {
            const el = document.getElementById("topbarNav");
            const c = bootstrap.Collapse.getInstance(el);
            if (c) c.hide();
        });
    });
});
