<?php // expect-none: DF011
namespace App\Controller;

class ExportController extends AbstractController
{
    public function export($request)
    {
        // the request only supplies the file's content; the path is fixed
        $body = $request->query->get('body');
        $this->filesystem->dumpFile('/srv/exports/report.txt', $body);
        $this->filesystem->appendToFile('/srv/exports/log.txt', $body);
    }
}
