// expect-none: DF005
import { readFile } from 'node:fs/promises';
import path from 'node:path';
export async function show(req, res) {
  res.json(JSON.parse(await readFile('/srv/data/' + path.basename(req.params.name), 'utf8')));
}
