// Trap: a constant navigation target.
if (!window.k) { location = "/home"; }
window.location.href = "/login?next=" + encodeURIComponent("/account");
