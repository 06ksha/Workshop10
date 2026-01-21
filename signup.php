<?php
require 'db.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid email format.";
    } elseif (empty($password) || strlen($password) < 8) {
        $message = "Password must be at least 8 characters.";
    } else {
        // Hashed password 
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        try {
            $stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
            $stmt->execute([$email, $hashedPassword]);
            $message = "User signed up successfully!";
            header('refresh: 2; url=login.php');
        } catch (Exception $e) {
            $message = "Something went wrong.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<body>
    <h2>Signup</h2>
    <?php if ($message) echo "<p>$message</p>"; ?>
    <form method="POST">
        Email: <input type="text" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        <button type="submit">Signup</button>
    </form>
</body>
</html>