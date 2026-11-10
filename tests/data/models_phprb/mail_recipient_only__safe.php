<?php // expect-none: DF002
function handler($request)
{
    // mb_send_mail's recipient is not passed to the shell; only $additional_params (5th) is
    mb_send_mail($_POST['to'], 'Hi', 'Body');
}
