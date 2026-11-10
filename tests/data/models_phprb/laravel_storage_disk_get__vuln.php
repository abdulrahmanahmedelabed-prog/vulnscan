<?php // expect: DF005
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $file = $request->input('file');
        $data = Storage::disk('local')->get('reports/' . $file);
    }
}
