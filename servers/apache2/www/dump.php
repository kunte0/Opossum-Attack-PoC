<?php

echo "dump.php\r\n";
var_dump($_POST);
error_log(basename(__FILE__) . "\n" . 'POSTBODY = ' . file_get_contents('php://input'));


?>

<img src='/subresource.png'/>