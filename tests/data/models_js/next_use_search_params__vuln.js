// expect: DF008
import { useSearchParams } from 'next/navigation';
export default function Login() {
  const params = useSearchParams();
  window.location.assign(params.get('next'));
}
