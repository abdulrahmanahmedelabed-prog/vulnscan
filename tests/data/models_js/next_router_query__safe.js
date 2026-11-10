// expect-none: DF013
import { useRouter } from 'next/router';
export default function Page() {
  const router = useRouter();
  document.getElementById('t').textContent = router.query.title;
}
