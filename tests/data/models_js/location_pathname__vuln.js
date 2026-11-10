// expect: DF013
function crumbs() {
  document.getElementById('crumbs').innerHTML = window.location.pathname.split('/').join(' &gt; ');
}
