<?php // expect-none: DF002
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $dir = $request->request->get('dir');
        $p = Process::fromShellCommandline('ls -la ' . escapeshellarg($dir));
    }
}
