<?php // expect: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $sid = $request->cookie('sid');
        $pdo->query("SELECT * FROM sessions WHERE sid = '" . $sid . "'");
    }
}
