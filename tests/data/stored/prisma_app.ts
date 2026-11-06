import express from 'express';
import { PrismaClient } from '@prisma/client';
import { execSync } from 'child_process';
const prisma = new PrismaClient();
const app = express();
app.post('/t', async (req, res) => {
  await prisma.task.create({ data: { cmd: req.body.cmd, owner: 'me' } });
});
app.get('/t', async (req, res) => {
  const t = await prisma.task.findUnique({ where: { id: 1 } });
  execSync(t.cmd);
  execSync(t.owner);
});
