// FP: any parameter named `request`/`req` is a taint source in ANY function (taint.py default request_params),
// even in a plain renderer that is not an entry point (React/Next internals: 1,244 DF010 + 294 DF005 on next.js)
const fs = require('fs');
function flushSegment(request, destination) {
  fs.writeFileSync(request.outPath, destination);   // DF005 "entry-point parameter request"
}
function renderModel(request, task) {
  return fetch(request.endpoint);                   // DF010 "entry-point parameter request"
}
// safe twin: identical code with another parameter name -> not reported
function flushSegment2(state, destination) { fs.writeFileSync(state.outPath, destination); }
module.exports = { flushSegment, renderModel, flushSegment2 };
