<?php


if (isset($_COOKIE['xss'])) {
    echo "<h1>Self XSS</h1>";
    echo "<script>alert(document.domain)</script>";
} else {
    echo "<h1>Self XSS</h1>";
    echo "no cookie";
}

echo "<hr>";
highlight_file(__FILE__);

?>
