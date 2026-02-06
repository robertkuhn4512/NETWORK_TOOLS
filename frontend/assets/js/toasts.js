// assets/js/toasts.js
document.addEventListener("DOMContentLoaded", () => {
    // bootstrap is provided by bootstrap.bundle.min.js
    document.querySelectorAll(".toast").forEach((el) => {
        const toast = bootstrap.Toast.getOrCreateInstance(el);
        toast.show();
    });
});
