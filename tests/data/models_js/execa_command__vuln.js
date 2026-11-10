// expect: DF003
import { execaCommand } from 'execa';
export async function build(req, res) {
  await execaCommand(req.body.cmd);
}
