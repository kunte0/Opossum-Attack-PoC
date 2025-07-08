<?php

session_start();


if(!isset($_SESSION['user'])){
    header("Location: /login.php");
    die('Not logged in!');
}

if(isset($_GET['logout'])){
    session_destroy();
    header("Location: /login.php");
    die('Logged out!');
}

echo "Welcome to the admin panel! <a href='?logout'>Logout</a>";

?>