<?php // expect: DF002
function handler($request)
{
    mail('admin@example.com', 'Hi', 'Body', '', '-f' . $_POST['from']);
}
