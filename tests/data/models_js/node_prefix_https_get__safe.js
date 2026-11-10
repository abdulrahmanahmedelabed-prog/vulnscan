// expect-none: DF010
import https from 'node:https';
export function fetchIt(req, res) {
  https.get('https://example.com/feed.xml', (r) => r.pipe(res));
}
