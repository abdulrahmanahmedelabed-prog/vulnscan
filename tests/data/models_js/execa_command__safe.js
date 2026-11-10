// expect-none: DF003
import { execa } from 'execa';
export async function build(req, res) {
  await execa('npm', ['run', 'build']);
}
