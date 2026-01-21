<?php
require 'db.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // 1. Validate email format [cite: 36]
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Invalid email format.";
    } 
    // 2. Ensure password is not empty and meets length requirements [cite: 38, 39]
    elseif (empty($password) || strlen($password) < 8) {
        $message = "Password must be at least 8 characters.";
    } else {
        // 3. Hash the password before saving [cite: 24]
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        try {
            // 4. Use prepared statements to prevent SQL Injection [cite: 32, 33]
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
<head>
    <title>Signup</title>
</head>
<body>
    <h2>Signup</h2>
    <?php if ($message) echo "<p>$message</p>"; ?>
    
    <form method="POST">
        Email: <input type="text" name="email" required><br>
        Password: <input type="password" name="password" required><br><br>
        <button type="submit">Signup</button>
    </form>

    <br>
    <a href="login.php">Go to Login</a> 
</body>
</html>