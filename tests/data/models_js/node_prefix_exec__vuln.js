// expect: DF002
import { exec } from 'node:child_process';
export function run(req, res) {
  exec('tar czf out.tgz ' + req.query.dir);
}
