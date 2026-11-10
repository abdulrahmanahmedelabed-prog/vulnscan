// expect-none: DF010
import ky from 'ky';
export async function proxy(req, res) {
  res.json(await ky.get('https://api.example.com/items', { searchParams: { q: req.query.u } }).json());
}
