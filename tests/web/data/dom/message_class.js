// Trap: inside a class, `this` is the element, not the window.
class Widget extends HTMLElement {
  connectedCallback() {
    this.addEventListener("message", (e) => { this.textContent = e.data; });
  }
}
