// Trap (WEB522): two closures each define "handler"; the registered one checks the origin. Minified code reuses
// short names like this in every closure, so the handler must be resolved in the registering scope.
function init() {
  function handler(e) {
    if (e.origin !== "https://app.example.test") { return; }
    document.getElementById("out").textContent = e.data;
  }
  window.addEventListener("message", handler);
}
function other() {
  function handler(e) { console.log(e.data); }
  document.getElementById("b").addEventListener("click", handler);
}
init();
other();
