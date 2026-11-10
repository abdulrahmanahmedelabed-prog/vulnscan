<?php // expect-none: DF011
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $path = $request->query->get('path');
        $this->filesystem->remove('/srv/cache/' . basename($path));
    }
}
