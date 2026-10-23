// The Content-Security-Policy of the web interface doesn't allow inline
// scripts, so the tooltips of the logged-in page are set up here.
document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((el) => new bootstrap.Tooltip(el));
