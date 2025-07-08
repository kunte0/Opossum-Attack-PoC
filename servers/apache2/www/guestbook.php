<?php

error_log(basename(__FILE__) . ' POST BODY: ' . file_get_contents('php://input'));

$cookie_opt = array (
    'secure' => true,     // or false
    'httponly' => true,    // or false
    'samesite' => 'Strict' // None || Lax  || Strict
);

setcookie('session', 'secret', $cookie_opt);

?>
<form method="POST" action="">
    <textarea name="comment" rows="4" cols="50"></textarea><br>
    <input type="submit" value="Submit">
</form>
<form method="POST" action="">
    <input type="submit" name="delete" value="Delete Comments">
</form>

<?php


// Check if the form is submitted
if (isset($_POST['comment']) && is_string($_POST['comment'])) {
    // Get the comment from the form
    $comment = $_POST['comment'];

    // Check if the comment is empty
    if (empty($comment)) {
        echo "Comment cannot be empty!<br>";
    } else {
        // Save the comment to a file
        file_put_contents('comments.txt', $comment . PHP_EOL, FILE_APPEND);
        echo "Comment saved!<br>";
    }
}

if (isset($_POST['delete'])) {
    // Delete the comments file
    if (file_exists('comments.txt')) {
        unlink('comments.txt');
        echo "Comments deleted!<br>";
    } else {
        echo "No comments to delete!<br>";
    }
}

// Display the comments
if (file_exists('comments.txt')) {
    $comments = file_get_contents('comments.txt');
    echo "<h2>Comments:</h2>";
    echo nl2br(htmlspecialchars($comments));
} else {
    echo "No comments yet!";
}