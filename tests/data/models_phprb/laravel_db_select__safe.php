<?php // expect-none: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $id = $request->input('id');
        return DB::select('SELECT * FROM users WHERE id = ?', [$id]);
    }
}
