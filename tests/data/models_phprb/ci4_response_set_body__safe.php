<?php // expect-none: DF013
class Demo extends CI_Controller
{
    public function index()
    {
        $m = $this->request->getGet('m');
        $this->response->setBody('<p>' . htmlspecialchars($m, ENT_QUOTES, 'UTF-8') . '</p>');
    }
}
