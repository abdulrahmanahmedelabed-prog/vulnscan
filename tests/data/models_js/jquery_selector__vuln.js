// expect: DF013
$(window).on('hashchange', function () {
  const el = $(location.hash);
  el.show();
});
