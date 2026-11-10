<?php // expect: DF013
class Demo extends BaseController
{
    public function index()
    {
        $q = $this->request->getGet('q');
        echo '<h1>' . $q . '</h1>';
    }
}
