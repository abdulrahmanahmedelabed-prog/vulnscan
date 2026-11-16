// Trap (WEB521): the classic HTTPS upgrade navigates to the current URL with a fixed edit.
if (location.protocol !== "https:") {
  location.href = location.href.replace("http:", "https:");
}
if (window.location.protocol === "http:") {
  window.location.replace("https://" + window.location.host + window.location.pathname + window.location.search);
}
