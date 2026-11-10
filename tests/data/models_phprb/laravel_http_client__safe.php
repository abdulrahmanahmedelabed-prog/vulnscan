<?php // expect-none: DF010
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $q = $request->input('q');
        $resp = Http::withHeaders(['Accept' => 'application/json'])->get('https://api.example.com/search', ['q' => $q]);
        return $resp->status();
    }
}
