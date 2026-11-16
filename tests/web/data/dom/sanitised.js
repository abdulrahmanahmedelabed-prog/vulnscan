// Trap: sanitised before insertion.
document.getElementById("out").innerHTML = DOMPurify.sanitize(location.hash.slice(1));
