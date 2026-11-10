<?php // expect: DF012
class Demo extends CI_Controller
{
    public function index()
    {
        $page = $this->input->get('page');
        $this->load->view('pages/' . $page);
    }
}
