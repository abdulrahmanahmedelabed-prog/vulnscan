// expect: DF010
import ky from 'ky';
export async function proxy(req, res) {
  res.json(await ky.get(req.query.u).json());
}
