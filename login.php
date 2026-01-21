<?php
require 'session.php'; 
require 'db.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 2. Verify the Secret Handshake [cite: 71]
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed.");
    }

    $email = $_POST['email'];
    $password = $_POST['password'];

    if (!empty($email) && !empty($password)) {
        // 3. Use the "Mail Slot" (Prepared Statement) to find the user [cite: 32]
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // 4. Verify the scrambled password [cite: 27]
        if ($user && password_verify($password, $user['password'])) {
            // 5. Give them a brand new ticket [cite: 53]
            session_regenerate_id(true); 
            $_SESSION['user_id'] = $user['id'];
            header('Location: dashboard.php');
            exit;
        } else {
            // 6. Be mysterious! Use a generic message [cite: 47]
            $error = "Invalid email or password"; 
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <?php if ($error) echo "<p style='color:red;'>$error</p>"; ?>
    
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        
        Email: <input type="text" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        <button type="submit">Login</button>
    </form>

    <br>
    <a href="signup.php">Go to Signup</a> 
</body>
</html>