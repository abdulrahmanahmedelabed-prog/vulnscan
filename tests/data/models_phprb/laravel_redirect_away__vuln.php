<?php // expect: DF008
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $next = $request->query('next');
        $r = redirect()->away($next);
    }
}
