// TP WEB521: location.assign with a query parameter.
var params = new URLSearchParams(window.location.search);
window.location.assign(params.get("next")); /*sink*/
