// expect: DF010
import https from 'node:https';
export function fetchIt(req, res) {
  https.get(req.query.url, (r) => r.pipe(res));
}
