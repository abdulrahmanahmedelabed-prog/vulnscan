// WEB520 tentative: $() gets a selector (starts with "#" or a constant that is not "<"); jQuery 1.9+ never parses
// it as HTML, older versions do.
if (location.hash) {
  $(location.hash).addClass("active"); /*sink*/
}
