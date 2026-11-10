// expect-none: DF013
function show() {
  const msg = new URLSearchParams(location.search).get('msg');
  document.getElementById('box').insertAdjacentHTML('beforeend', DOMPurify.sanitize(msg));
}
