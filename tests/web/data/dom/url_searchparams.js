// TP WEB520: a URL object built from the page URL is a browser source.
const url = new URL(window.location.href);
const name = url.searchParams.get("name");
document.getElementById("out").innerHTML = "<b>" + name + "</b>"; /*sink*/
