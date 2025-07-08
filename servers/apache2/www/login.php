<?php

session_start();

var_dump($_POST);

if(isset($_SESSION['user'])){
    header("Location: /admin.php");
    die('Already logged in!');
}

if(isset($_POST['username']) && isset($_POST['password'])){
    if($_POST['username'] == 'admin' && $_POST['password'] == 'admin'){
        $_SESSION['user'] = 'admin';
        header("Location: /admin.php");
        die('Logged in!');
    }
    else{
        echo "Invalid username or password";
    }
}

if(isset($_GET['username']) && isset($_GET['password'])){
    if($_GET['username'] == 'admin' && $_GET['password'] == 'admin'){
        $_SESSION['user'] = 'admin';
        header("Location: /admin.php");
        die('Logged in!');
    }
    else{
        echo "Invalid username or password";
    }
}


?>
<h1>Login</h1>
<form method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>