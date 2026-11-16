// Trap: messages from a same-origin worker, a MessagePort and server-sent events need no origin check.
var w = new Worker("/static/worker.js");
w.onmessage = function (e) { document.getElementById("out").textContent = e.data; };
var es = new EventSource("/events");
es.addEventListener("message", function (e) { console.log(e.data); });
