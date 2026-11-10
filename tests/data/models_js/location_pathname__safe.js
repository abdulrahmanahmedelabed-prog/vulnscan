// expect-none: DF013
function crumbs() {
  document.getElementById('crumbs').textContent = window.location.pathname.split('/').join(' > ');
}
