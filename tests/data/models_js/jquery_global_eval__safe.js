// expect-none: DF001 DF013
function load() {
  const code = location.hash.slice(1);
  $('#out').text(code);
}
