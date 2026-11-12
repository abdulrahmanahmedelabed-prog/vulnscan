const Log = require('./log');
// FP: any `event.message` / `event.data` / `context.payload` is treated as a remote source (models sources roots include "event")
function onCompilation(event) {
  Log.error(event.message);
}
module.exports = { onCompilation };
