// expect-none: DF008
import { permanentRedirect } from 'next/navigation';
export async function GET(request: Request) {
  permanentRedirect('/new-home');
}
