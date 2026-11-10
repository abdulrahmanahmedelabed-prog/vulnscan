// expect: DF005
import { readFile } from 'node:fs/promises';
export async function show(req, res) {
  res.json(JSON.parse(await readFile('/srv/data/' + req.params.name, 'utf8')));
}
