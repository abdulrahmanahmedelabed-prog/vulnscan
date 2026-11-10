<?php // expect-none: DF012
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $page = $request->input('page');
        $config = File::getRequire(base_path('config/app.php'));
    }
}
