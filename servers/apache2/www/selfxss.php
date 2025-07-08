<?php


if (isset($_COOKIE['xss'])) {
    echo "<h1>Self XSS</h1>";
    echo "<script>alert(1)</script>";
} else {
    echo "<h1>Self XSS</h1>";
    echo "no cookie";
}

?>