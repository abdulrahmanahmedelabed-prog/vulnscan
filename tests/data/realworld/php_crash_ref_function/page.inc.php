<?php
// return-by-reference function: RecursionError in the frontend -> the WHOLE file becomes an empty module
function &sessionGrab() {
    return $_SESSION['app'];
}

function show() {
    echo "<p>Hello " . $_GET['name'] . "</p>";   // reflected XSS: missed
    system("ping " . $_GET['host']);             // command injection: missed by dataflow
}
show();
