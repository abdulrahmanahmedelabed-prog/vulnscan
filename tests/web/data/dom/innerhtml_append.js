// TP WEB520: compound assignment (+=) to innerHTML.
var list = document.getElementById("list");
list.innerHTML += "<li>" + location.hash.slice(1) + "</li>"; /*sink*/
