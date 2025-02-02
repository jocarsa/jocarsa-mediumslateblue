<?php
session_start();
header('Content-Type: application/json');

// Enable detailed error reporting (Development Only)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Connect to SQLite database
try {
    $db = new PDO('sqlite:../../../databases/steelblue.sqlite'); // Ensure the path is correct relative to backend.php
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e){
    error_log("Database Connection Error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Failed to connect to the database.']);
    exit;
}

// Create tables if they don't exist
try {
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        content TEXT DEFAULT '',
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
} catch(PDOException $e){
    error_log("Table Creation Error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Failed to create tables.']);
    exit;
}

// Get the JSON input
$input = json_decode(file_get_contents('php://input'), true);
$action = isset($input['action']) ? $input['action'] : '';

switch($action){
    case 'signup':
        signup($db, $input);
        break;
    case 'login':
        login($db, $input);
        break;
    case 'logout':
        logout();
        break;
    case 'check_session':
        check_session();
        break;
    case 'create_document':
        create_document($db, $input);
        break;
    case 'get_documents':
        get_documents($db);
        break;
    case 'rename_document':
        rename_document($db, $input);
        break;
    case 'delete_document':
        delete_document($db, $input);
        break;
    case 'get_document':
        get_document($db, $input);
        break;
    case 'save_document':
        save_document($db, $input);
        break;
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
}

// Function to handle signup
function signup($db, $input){
    if(!isset($input['username']) || !isset($input['password'])){
        echo json_encode(['success' => false, 'message' => 'Username and password required']);
        exit;
    }

    $username = trim($input['username']);
    $password = $input['password'];

    if(strlen($username) < 3 || strlen($password) < 6){
        echo json_encode(['success' => false, 'message' => 'Username must be at least 3 characters and password at least 6 characters']);
        exit;
    }

    // Check if username exists
    $stmt = $db->prepare("SELECT id FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    if($stmt->fetch()){
        echo json_encode(['success' => false, 'message' => 'Username already taken']);
        exit;
    }

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Insert into database
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    try{
        $stmt->execute([':username' => $username, ':password' => $hashed_password]);
        echo json_encode(['success' => true]);
    } catch(PDOException $e){
        error_log("Signup Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
}

// Function to handle login
function login($db, $input){
    if(!isset($input['username']) || !isset($input['password'])){
        echo json_encode(['success' => false, 'message' => 'Username and password required']);
        exit;
    }

    $username = trim($input['username']);
    $password = $input['password'];

    // Fetch user
    $stmt = $db->prepare("SELECT id, password FROM users WHERE username = :username");
    if(!$stmt){
        echo json_encode(['success' => false, 'message' => 'Failed to prepare statement']);
        exit;
    }

    try {
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch(PDOException $e){
        error_log("Login Execution Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
        exit;
    }

    if(!$user){
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        exit;
    }

    if(!password_verify($password, $user['password'])){
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        exit;
    }

    // Regenerate session ID to prevent session fixation
    session_regenerate_id(true);

    // Set session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $username;

    echo json_encode(['success' => true]);
}

// Function to handle logout
function logout(){
    session_unset();
    session_destroy();
    echo json_encode(['success' => true]);
}

// Function to check session
function check_session(){
    if(isset($_SESSION['user_id'])){
        echo json_encode(['logged_in' => true]);
    } else {
        echo json_encode(['logged_in' => false]);
    }
}

// Function to create a new document
function create_document($db, $input){
    if(!isset($_SESSION['user_id'])){
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        exit;
    }

    if(!isset($input['name']) || trim($input['name']) === ''){
        echo json_encode(['success' => false, 'message' => 'Document name is required']);
        exit;
    }

    $name = trim($input['name']);
    $user_id = $_SESSION['user_id'];

    // Check if a document with the same name exists for the user
    $stmt = $db->prepare("SELECT COUNT(*) FROM documents WHERE user_id = :user_id AND name = :name");
    $stmt->execute([':user_id' => $user_id, ':name' => $name]);
    $count = $stmt->fetchColumn();

    if($count > 0){
        echo json_encode(['success' => false, 'message' => 'A document with this name already exists']);
        exit;
    }

    // Insert into database
    $stmt = $db->prepare("INSERT INTO documents (user_id, name) VALUES (:user_id, :name)");
    try{
        $stmt->execute([':user_id' => $user_id, ':name' => $name]);
        echo json_encode(['success' => true]);
    } catch(PDOException $e){
        error_log("Create Document Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
}

// Function to get all documents for the user
function get_documents($db){
    if(!isset($_SESSION['user_id'])){
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        exit;
    }

    $user_id = $_SESSION['user_id'];
    $stmt = $db->prepare("SELECT id, name FROM documents WHERE user_id = :user_id ORDER BY id DESC");
    try{
        $stmt->execute([':user_id' => $user_id]);
        $documents = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['success' => true, 'documents' => $documents]);
    } catch(PDOException $e){
        error_log("Get Documents Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
}

// Function to rename a document
function rename_document($db, $input){
    if(!isset($_SESSION['user_id'])){
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        exit;
    }

    if(!isset($input['id']) || !isset($input['new_name'])){
        echo json_encode(['success' => false, 'message' => 'Invalid parameters']);
        exit;
    }

    $id = intval($input['id']);
    $new_name = trim($input['new_name']);

    if(strlen($new_name) < 1){
        echo json_encode(['success' => false, 'message' => 'Name cannot be empty']);
        exit;
    }

    $user_id = $_SESSION['user_id'];

    // Check if document exists and belongs to user
    $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
    $stmt->execute([':id' => $id, ':user_id' => $user_id]);
    if(!$stmt->fetch()){
        echo json_encode(['success' => false, 'message' => 'Document not found']);
        exit;
    }

    // Check if new name already exists for the user
    $stmt = $db->prepare("SELECT COUNT(*) FROM documents WHERE user_id = :user_id AND name = :name AND id != :id");
    $stmt->execute([':user_id' => $user_id, ':name' => $new_name, ':id' => $id]);
    $count = $stmt->fetchColumn();
    if($count > 0){
        echo json_encode(['success' => false, 'message' => 'Another document with this name already exists']);
        exit;
    }

    // Update name
    $stmt = $db->prepare("UPDATE documents SET name = :name WHERE id = :id");
    try{
        $stmt->execute([':name' => $new_name, ':id' => $id]);
        echo json_encode(['success' => true]);
    } catch(PDOException $e){
        error_log("Rename Document Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
}

// Function to delete a document
function delete_document($db, $input){
    if(!isset($_SESSION['user_id'])){
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        exit;
    }

    if(!isset($input['id'])){
        echo json_encode(['success' => false, 'message' => 'Invalid parameters']);
        exit;
    }

    $id = intval($input['id']);
    $user_id = $_SESSION['user_id'];

    // Check if document exists and belongs to user
    $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
    $stmt->execute([':id' => $id, ':user_id' => $user_id]);
    if(!$stmt->fetch()){
        echo json_encode(['success' => false, 'message' => 'Document not found']);
        exit;
    }

    // Delete document
    $stmt = $db->prepare("DELETE FROM documents WHERE id = :id");
    try{
        $stmt->execute([':id' => $id]);
        echo json_encode(['success' => true]);
    } catch(PDOException $e){
        error_log("Delete Document Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
}

// Function to get a specific document's content
function get_document($db, $input){
    if(!isset($_SESSION['user_id'])){
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        exit;
    }

    if(!isset($input['id'])){
        echo json_encode(['success' => false, 'message' => 'Invalid parameters']);
        exit;
    }

    $id = intval($input['id']);
    $user_id = $_SESSION['user_id'];

    // Logging for debugging
    error_log("Fetching document with ID: $id for user ID: $user_id");

    // Fetch document
    $stmt = $db->prepare("SELECT content FROM documents WHERE id = :id AND user_id = :user_id");
    try{
        $stmt->execute([':id' => $id, ':user_id' => $user_id]);
        $doc = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch(PDOException $e){
        error_log("Get Document Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
        exit;
    }

    if(!$doc){
        error_log("Document not found: ID $id for user ID: $user_id");
        echo json_encode(['success' => false, 'message' => 'Document not found']);
        exit;
    }

    // Log the content fetched (first 100 characters)
    error_log("Fetched content for document ID $id: " . substr($doc['content'], 0, 100));

    echo json_encode(['success' => true, 'content' => $doc['content']]);
}

// Function to save a document's content
function save_document($db, $input){
    if(!isset($_SESSION['user_id'])){
        echo json_encode(['success' => false, 'message' => 'Not authenticated']);
        exit;
    }

    if(!isset($input['id']) || !isset($input['content'])){
        echo json_encode(['success' => false, 'message' => 'Invalid parameters']);
        exit;
    }

    $id = intval($input['id']);
    $content = $input['content'];
    $user_id = $_SESSION['user_id'];

    // Check if document exists and belongs to user
    $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
    try{
        $stmt->execute([':id' => $id, ':user_id' => $user_id]);
        if(!$stmt->fetch()){
            echo json_encode(['success' => false, 'message' => 'Document not found']);
            exit;
        }
    } catch(PDOException $e){
        error_log("Save Document Check Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
        exit;
    }

    // Update content
    $stmt = $db->prepare("UPDATE documents SET content = :content WHERE id = :id");
    try{
        $stmt->execute([':content' => $content, ':id' => $id]);
        echo json_encode(['success' => true]);
    } catch(PDOException $e){
        error_log("Save Document Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
}
?>

