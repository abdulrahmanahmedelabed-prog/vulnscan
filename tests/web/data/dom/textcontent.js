// Trap: textContent is not an HTML sink.
document.getElementById("out").textContent = location.hash;
document.title = decodeURIComponent(location.search);
