// TP WEB522 (firm): message data reaches eval without an origin check.
function onMsg(event) {
  var cmd = event.data;
  eval(cmd);
}
window.onmessage = onMsg; /*sink*/
