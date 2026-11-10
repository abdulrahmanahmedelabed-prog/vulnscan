<?php // expect: DF010
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $url = $request->input('callback');
        $resp = Http::withHeaders(['Accept' => 'application/json'])->get($url);
        return $resp->status();
    }
}
