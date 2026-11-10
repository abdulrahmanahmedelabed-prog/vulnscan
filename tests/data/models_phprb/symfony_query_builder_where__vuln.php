<?php // expect: DF004
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DemoController extends Controller
{
    public function show($request)
    {
        $name = $request->query->get('name');
        $qb = $this->em->createQueryBuilder();
        $qb->select('u')->from('App\\Entity\\User', 'u')->where("u.name = '" . $name . "'");
    }
}
