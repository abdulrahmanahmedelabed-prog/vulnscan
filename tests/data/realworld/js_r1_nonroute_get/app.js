// Callbacks passed to ANY .get/.all/.use(...) are treated as route handlers and all their params as tainted.
const cp = require('child_process');
const cache = require('./cache');

function warm() {
  // Not a route: cache.get(key, cb) / Model.all(cb). Values come from our own store.
  cache.get('build-cmd', function (err, cmd) {
    cp.exec(cmd);                 // reported as DF002 from "entry-point parameter cmd" (FP)
  });
}

// safe twin is the same code with a non-route method name: not reported
function warm2() {
  cache.fetch('build-cmd', function (err, cmd) {
    cp.exec(cmd);
  });
}
module.exports = { warm, warm2 };
