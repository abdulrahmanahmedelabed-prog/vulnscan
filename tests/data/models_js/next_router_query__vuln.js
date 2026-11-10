// expect: DF013
import { useRouter } from 'next/router';
export default function Page() {
  const router = useRouter();
  document.getElementById('t').innerHTML = router.query.title;
}
