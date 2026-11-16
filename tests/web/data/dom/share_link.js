// Trap (WEB521): setting a link's href is not a navigation (spec §2.6 sinks: location and window.open).
var share = document.getElementById("share");
share.href = "https://twitter.example/intent?url=" + encodeURIComponent(location.href);
document.querySelectorAll("a.lang").forEach(function (a) {
  a.href = location.pathname + "?lang=" + a.dataset.lang;
});
