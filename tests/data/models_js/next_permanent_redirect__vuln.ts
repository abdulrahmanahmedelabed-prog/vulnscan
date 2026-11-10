// expect: DF008
import { permanentRedirect } from 'next/navigation';
export async function GET(request: Request) {
  const u = new URL(request.url).searchParams.get('to');
  permanentRedirect(u);
}
