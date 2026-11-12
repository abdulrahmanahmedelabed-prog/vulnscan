<?php
$target = $argv[1];
passthru('backup-tool ' . $target);
