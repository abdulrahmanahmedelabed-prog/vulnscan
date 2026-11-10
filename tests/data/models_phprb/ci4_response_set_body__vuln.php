<?php // expect: DF013
class Demo extends CI_Controller
{
    public function index()
    {
        $m = $this->request->getGet('m');
        $this->response->setBody('<p>' . $m . '</p>');
    }
}
