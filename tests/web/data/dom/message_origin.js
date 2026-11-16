// Trap: the handler checks the origin.
window.addEventListener("message", function (e) {
  if (e.origin !== "https://app.example.test") { return; }
  document.getElementById("out").textContent = e.data;
});
