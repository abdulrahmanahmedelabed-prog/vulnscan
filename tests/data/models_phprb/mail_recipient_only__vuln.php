<?php // expect: DF002
function handler($request)
{
    mb_send_mail('admin@example.com', 'Hi', 'Body', '', '-f' . $_POST['from']);
}
