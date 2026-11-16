// TP WEB522 (firm): a class method registered with bind(this); the data reaches innerHTML.
class Widget {
  constructor() {
    window.addEventListener("message", this.onMessage.bind(this)); /*sink*/
  }
  onMessage(event) {
    document.getElementById("out").innerHTML = event.data;
  }
}
new Widget();
