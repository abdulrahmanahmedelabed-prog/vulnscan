// TP WEB521: "//" + attacker host is an absolute URL to any site.
var p = new URLSearchParams(location.search);
location.href = "//" + p.get("host") + "/welcome"; /*sink*/
