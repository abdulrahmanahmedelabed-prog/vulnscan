<?php // expect: DF011
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $name = $request->file('doc')->getClientOriginalName();
        unlink('/var/uploads/' . $name);
    }
}
