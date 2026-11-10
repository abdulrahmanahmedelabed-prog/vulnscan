<?php // expect: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $table = $request->query('table');
        DB::connection('mysql')->statement("TRUNCATE " . $table);
    }
}
