// expect-none: DF013
$(window).on('hashchange', function () {
  const el = $('#' + CSS.escape(location.hash.slice(1)));
  el.show();
});
