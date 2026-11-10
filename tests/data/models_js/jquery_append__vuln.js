// expect: DF013
function greet() {
  const name = new URLSearchParams(location.search).get('name');
  $('#greeting').append('<b>' + name + '</b>');
}
