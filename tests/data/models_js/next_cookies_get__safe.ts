// expect-none: DF001
import { cookies } from 'next/headers';
export async function GET() {
  const theme = cookies().get('theme');
  return JSON.parse(theme);
}
