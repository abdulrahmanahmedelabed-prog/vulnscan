<?php // expect: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $name = $request->input('name');
        return User::where('active', 1)->orWhereRaw("name = '" . $name . "'")->get();
    }
}
