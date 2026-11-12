import { getServerSession } from 'next-auth';
import db from '../../../lib/db';

export default async function handler(req, res) {
  const session = await getServerSession(req, res);
  if (!session) {
    return res.status(401).end();
  }
  if (req.method === 'DELETE') {
    await db.query('DELETE FROM users WHERE id = ' + req.query.id);
  }
  res.json({ id: req.query.id });
}
