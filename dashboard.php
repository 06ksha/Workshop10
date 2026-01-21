<?php
require 'session.php'; 
require 'db.php';

if (isset($_POST['logout'])) {
    session_unset(); 
    session_destroy(); 
    header("Location: login.php");
    exit;
}

$user_email = '';
if (isset($_SESSION['user_id'])) {
    
    $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
    
    if ($user) {
        
        $user_email = htmlspecialchars($user['email']);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h1>Dashboard</h1>
    
    <?php if ($user_email): ?>
        <p>Welcome, <?php echo $user_email; ?></p>
        <form method="POST">
            <button type="submit" name="logout">Logout</button>
        </form>
    <?php else: ?>
        <p>You are not logged in.</p>
        <a href="login.php"><button>Login</button></a>
    <?php endif; ?>
</body>
</html>