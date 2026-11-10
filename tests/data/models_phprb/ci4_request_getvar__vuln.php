<?php // expect: DF004
class Demo extends CI_Controller
{
    public function index()
    {
        $id = $this->request->getVar('id');
        $this->db->simpleQuery('DELETE FROM items WHERE id = ' . $id);
    }
}
