<?php // expect-none: DF002
function handler($request)
{
    mail('admin@example.com', 'Hi', 'Body', '', '-f' . escapeshellarg($_POST['from']));
}
