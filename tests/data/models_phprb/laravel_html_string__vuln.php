<?php // expect: DF013
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $bio = $request->input('bio');
        echo new HtmlString($bio);
    }
}
