// Trap: a local variable called location is not window.location.
(function () {
  var location = {};
  location = window.name;
  console.log(location);
})();
