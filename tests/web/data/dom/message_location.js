// TP WEB522 (firm): the message data becomes the navigation target.
addEventListener("message", function (ev) { /*sink*/
  var url = ev.data.url;
  location = url;
});
