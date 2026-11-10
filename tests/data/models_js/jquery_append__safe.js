// expect-none: DF013
function greet() {
  const name = new URLSearchParams(location.search).get('name');
  $('#greeting').text(name);
  const fd = new FormData();
  fd.append('name', name);
  const parts = [];
  parts.push(name);
}
