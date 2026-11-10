// expect: DF001
function load() {
  const code = location.hash.slice(1);
  $.globalEval(code);
}
