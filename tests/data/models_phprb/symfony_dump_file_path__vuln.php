<?php // expect: DF011
namespace App\Controller;

class ExportController extends AbstractController
{
    public function export($request)
    {
        $name = $request->query->get('name');
        $this->filesystem->dumpFile('/srv/exports/' . $name, 'report');
    }
}
