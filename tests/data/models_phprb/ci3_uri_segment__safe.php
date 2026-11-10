<?php // expect-none: DF005
class Demo extends CI_Controller
{
    public function index()
    {
        $f = $this->uri->segment(3);
        readfile('/srv/docs/' . basename($f));
    }
}
