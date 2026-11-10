<?php // expect-none: DF002
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $file = $request->input('file');
        Process::run("convert " . escapeshellarg($file) . " out.png");
    }
}
