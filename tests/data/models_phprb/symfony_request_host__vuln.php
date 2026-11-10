<?php // expect: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $host = $request->getHost();
        $this->connection->executeQuery("SELECT * FROM tenants WHERE host = '" . $host . "'");
    }
}
