<?php
// secure_login.php
// This file uses prepared statements to prevent SQL Injection.

$conn = mysqli_connect("localhost", "root", "", "demo_db");
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

$username = $_GET['username'];
$password = $_GET['password'];

// Prepare the SQL statement with placeholders
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo "Logged in successfully!";
} else {
    echo "Invalid credentials.";
}

$stmt->close();
mysqli_close($conn);
?>
