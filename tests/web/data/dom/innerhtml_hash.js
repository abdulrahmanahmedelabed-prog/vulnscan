// TP WEB520: the fragment is written into the page as HTML.
var out = document.getElementById("out");
out.innerHTML = decodeURIComponent(location.hash.slice(1)); /*sink*/
