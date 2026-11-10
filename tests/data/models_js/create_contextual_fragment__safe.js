// expect-none: DF013
function render() {
  const frag = document.createRange().createContextualFragment(DOMPurify.sanitize(window.location.hash.slice(1)));
  document.body.appendChild(frag);
}
