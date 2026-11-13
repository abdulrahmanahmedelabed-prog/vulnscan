// TP WEB521: window.open with the fragment.
document.getElementById("go").addEventListener("click", function () {
  window.open(location.hash.slice(1)); /*sink*/
});
