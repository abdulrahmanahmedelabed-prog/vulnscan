// Trap: the handler hands the event to a function that checks the origin.
function trusted(ev) {
  return ev.origin === "https://app.example.test";
}
function handle(ev) {
  if (!trusted(ev)) { return; }
  document.getElementById("out").textContent = ev.data;
}
window.addEventListener("message", function (e) { handle(e); });
