<?php // expect-none: DF013
class Demo extends BaseController
{
    public function index()
    {
        $q = $this->request->getGet('q');
        echo '<h1>' . esc($q) . '</h1>';
    }
}
