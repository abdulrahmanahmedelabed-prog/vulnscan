<?php // expect-none: DF005
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $f = $request->query->get('f');
        $resp = new BinaryFileResponse('/srv/files/' . basename($f));
    }
}
