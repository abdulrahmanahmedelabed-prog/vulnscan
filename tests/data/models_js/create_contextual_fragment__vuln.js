// expect: DF013
function render() {
  const frag = document.createRange().createContextualFragment(window.location.hash.slice(1));
  document.body.appendChild(frag);
}
