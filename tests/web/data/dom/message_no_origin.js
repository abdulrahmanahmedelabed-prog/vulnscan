// TP WEB522 (tentative): the handler never reads event.origin.
window.addEventListener("message", function (e) { /*sink*/
  document.getElementById("out").textContent = e.data;
});
