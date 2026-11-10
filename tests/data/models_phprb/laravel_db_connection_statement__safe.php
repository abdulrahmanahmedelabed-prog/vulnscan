<?php // expect-none: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $table = $request->query('table');
        DB::connection('mysql')->statement('DELETE FROM audit WHERE name = ?', [$table]);
    }
}
