// Trap (WEB521): attacker data only after a prefix that fixes the origin (relative path, query, or fixed host).
var params = new URLSearchParams(location.search);
window.location.href = "/search?q=" + encodeURIComponent(params.get("q"));
var next = "/login?next=" + location.pathname;
location = next;
if (location.hostname !== "www.example.test") {
  location.href = "https://www.example.test" + location.pathname;
}
location.assign(`?page=${params.get("page")}`);
