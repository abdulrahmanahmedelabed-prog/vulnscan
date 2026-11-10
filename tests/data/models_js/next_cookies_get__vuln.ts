// expect: DF001
import { cookies } from 'next/headers';
export async function GET() {
  const theme = cookies().get('theme');
  return new Function('return ' + theme)();
}
