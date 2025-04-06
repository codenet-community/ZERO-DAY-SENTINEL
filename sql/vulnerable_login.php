<?php
// vulnerable_login.php
// This file demonstrates an SQL Injection vulnerability. Do not use this in production!

// Connect to the database
$conn = mysqli_connect("localhost", "root", "", "demo_db");
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Get user input (using GET for simplicity)
$username = $_GET['username'];
$password = $_GET['password'];

// Vulnerable query: directly inserting user input into the SQL query
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    echo "Logged in successfully!";
} else {
    echo "Invalid credentials.";
}

mysqli_close($conn);
?>
