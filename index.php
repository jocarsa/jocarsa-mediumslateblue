<?php

// index.ph
// Enable error reporting for development (Disable in production)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();

// Set content type
//header('Content-Type: text/html; charset=UTF-8');
//include "../red/index.php"; 

// Connect to SQLite database
try {
    $db = new PDO('sqlite:../databases/mediumslateblue.sqlite'); // Ensure the path is correct
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // Create tables if they don't exist
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
        share_hash TEXT UNIQUE,
        expiry_date DATETIME DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
} catch (PDOException $e){
    die("Database Connection Error: " . $e->getMessage());
}

// Initialize variables
$error = '';
$success = '';
$action = isset($_GET['action']) ? $_GET['action'] : '';

// Handle Logout
if ($action == 'logout') {
    session_unset();
    session_destroy();
    redirect('index.php');
}

// Handle User Signup
if ($action == 'signup' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = isset($_POST['signup_username']) ? trim($_POST['signup_username']) : '';
    $password = isset($_POST['signup_password']) ? $_POST['signup_password'] : '';

    // Validate inputs
    if (strlen($username) < 3 || strlen($password) < 6) {
        $error = 'Username must be at least 3 characters and password at least 6 characters long.';
    } else {
        // Check if username exists
        $stmt = $db->prepare("SELECT id FROM users WHERE username = :username");
        $stmt->execute([':username' => $username]);
        if ($stmt->fetch()) {
            $error = 'Username is already taken.';
        } else {
            // Hash the password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            // Insert into database
            $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
            try {
                $stmt->execute([':username' => $username, ':password' => $hashed_password]);
                $success = 'Registration successful! Please log in.';
                $action = 'login'; // Redirect to login
            } catch (PDOException $e){
                $error = 'Database error during registration.';
            }
        }
    }
}

// Handle User Login
if ($action == 'login' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = isset($_POST['login_username']) ? trim($_POST['login_username']) : '';
    $password = isset($_POST['login_password']) ? $_POST['login_password'] : '';

    // Fetch user
    $stmt = $db->prepare("SELECT id, password FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        // Regenerate session ID
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $username;
        redirect('index.php');
    } else {
        $error = 'Invalid username or password.';
    }
}

// Handle Document Creation
if ($action == 'create_document' && $_SERVER['REQUEST_METHOD'] == 'POST' && is_logged_in()) {
    $doc_name = isset($_POST['document_name']) ? trim($_POST['document_name']) : '';

    if ($doc_name == '') {
        $error = 'Document name cannot be empty.';
    } else {
        // Check for duplicate name
        $stmt = $db->prepare("SELECT COUNT(*) FROM documents WHERE user_id = :user_id AND name = :name");
        $stmt->execute([':user_id' => $_SESSION['user_id'], ':name' => $doc_name]);
        if ($stmt->fetchColumn() > 0) {
            $error = 'A document with this name already exists.';
        } else {
            // Insert new document with creation and update dates
            $stmt = $db->prepare("INSERT INTO documents (user_id, name, created_at, updated_at) VALUES (:user_id, :name, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)");
            try {
                $stmt->execute([':user_id' => $_SESSION['user_id'], ':name' => $doc_name]);
                redirect('index.php');
            } catch (PDOException $e){
                $error = 'Database error during document creation.';
            }
        }
    }
}

// Handle Document Renaming
if ($action == 'rename_document' && $_SERVER['REQUEST_METHOD'] == 'POST' && is_logged_in()) {
    $doc_id = isset($_POST['doc_id']) ? intval($_POST['doc_id']) : 0;
    $new_name = isset($_POST['new_name']) ? trim($_POST['new_name']) : '';

    if ($doc_id == 0 || $new_name == '') {
        $error = 'Invalid document ID or name.';
    } else {
        // Verify document ownership
        $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $doc_id, ':user_id' => $_SESSION['user_id']]);
        if (!$stmt->fetch()) {
            $error = 'Document not found.';
        } else {
            // Check for duplicate name
            $stmt = $db->prepare("SELECT COUNT(*) FROM documents WHERE user_id = :user_id AND name = :name AND id != :id");
            $stmt->execute([':user_id' => $_SESSION['user_id'], ':name' => $new_name, ':id' => $doc_id]);
            if ($stmt->fetchColumn() > 0) {
                $error = 'Another document with this name already exists.';
            } else {
                // Update name and modification date
                $stmt = $db->prepare("UPDATE documents SET name = :name, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
                try {
                    $stmt->execute([':name' => $new_name, ':id' => $doc_id]);
                    redirect('index.php');
                } catch (PDOException $e){
                    $error = 'Database error during renaming.';
                }
            }
        }
    }
}

// Handle Document Deletion
if ($action == 'delete_document' && $_SERVER['REQUEST_METHOD'] == 'POST' && is_logged_in()) {
    $doc_id = isset($_POST['doc_id']) ? intval($_POST['doc_id']) : 0;

    if ($doc_id == 0) {
        $error = 'Invalid document ID.';
    } else {
        // Verify document ownership
        $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $doc_id, ':user_id' => $_SESSION['user_id']]);
        if (!$stmt->fetch()) {
            $error = 'Document not found.';
        } else {
            // Delete document
            $stmt = $db->prepare("DELETE FROM documents WHERE id = :id");
            try {
                $stmt->execute([':id' => $doc_id]);
                redirect('index.php');
            } catch (PDOException $e){
                $error = 'Database error during deletion.';
            }
        }
    }
}

// Handle Document Saving
if ($action == 'save_document' && $_SERVER['REQUEST_METHOD'] == 'POST' && is_logged_in()) {
    $doc_id = isset($_POST['doc_id']) ? intval($_POST['doc_id']) : 0;
    $content = isset($_POST['content']) ? $_POST['content'] : '';

    if ($doc_id == 0) {
        $error = 'Invalid document ID.';
    } else {
        // Verify document ownership
        $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $doc_id, ':user_id' => $_SESSION['user_id']]);
        if (!$stmt->fetch()) {
            $error = 'Document not found.';
        } else {
            // Update content and modification date
            $stmt = $db->prepare("UPDATE documents SET content = :content, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
            try {
                $stmt->execute([':content' => $content, ':id' => $doc_id]);
                $success = 'Document saved successfully.';
                redirect('index.php?action=edit&doc_id=' . $doc_id);
            } catch (PDOException $e){
                $error = 'Database error during saving.';
            }
        }
    }
}

// Handle Document Sharing
if ($action == 'share_document' && $_SERVER['REQUEST_METHOD'] == 'POST' && is_logged_in()) {
    $doc_id = isset($_POST['doc_id']) ? intval($_POST['doc_id']) : 0;

    if ($doc_id == 0) {
        $error = 'Invalid document ID.';
    } else {
        // Verify document ownership
        $stmt = $db->prepare("SELECT id, share_hash, name FROM documents WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $doc_id, ':user_id' => $_SESSION['user_id']]);
        $doc = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$doc) {
            $error = 'Document not found.';
        } else {
            if (empty($doc['share_hash'])) {
                // Generate unique hash for sharing
                try {
                    if (function_exists('random_bytes')) {
                        $share_hash = bin2hex(random_bytes(16)); // 32-character hex string
                    } elseif (function_exists('openssl_random_pseudo_bytes')) {
                        $share_hash = bin2hex(openssl_random_pseudo_bytes(16));
                    } else {
                        throw new Exception('No secure random byte generator available.');
                    }

                    // Set expiration to 7 days
                    $expiry_date = date('Y-m-d H:i:s', strtotime('+7 days'));

                    // Update document with new share_hash and expiry_date
                    $stmt = $db->prepare("UPDATE documents SET share_hash = :share_hash, expiry_date = :expiry_date, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
                    $stmt->execute([':share_hash' => $share_hash, ':expiry_date' => $expiry_date, ':id' => $doc_id]);
                } catch (Exception $e) {
                    $error = 'Error generating share link.';
                }
            } else {
                $share_hash = $doc['share_hash'];
            }

            if (!$error) {
                $share_url = generate_share_url($share_hash);
                $success = "Share URL: <a href=\"$share_url\" target=\"_blank\">$share_url</a>";
            }
        }
    }
}

// Handle Regenerating Share Link (Optional)
if ($action == 'regenerate_share_link' && $_SERVER['REQUEST_METHOD'] == 'POST' && is_logged_in()) {
    $doc_id = isset($_POST['doc_id']) ? intval($_POST['doc_id']) : 0;

    if ($doc_id == 0) {
        $error = 'Invalid document ID.';
    } else {
        // Verify document ownership
        $stmt = $db->prepare("SELECT id FROM documents WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $doc_id, ':user_id' => $_SESSION['user_id']]);
        $doc = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$doc) {
            $error = 'Document not found.';
        } else {
            // Generate new share_hash
            try {
                if (function_exists('random_bytes')) {
                    $share_hash = bin2hex(random_bytes(16)); // 32-character hex string
                } elseif (function_exists('openssl_random_pseudo_bytes')) {
                    $share_hash = bin2hex(openssl_random_pseudo_bytes(16));
                } else {
                    throw new Exception('No secure random byte generator available.');
                }

                // Set expiration to 7 days
                $expiry_date = date('Y-m-d H:i:s', strtotime('+7 days'));

                // Update document with new share_hash and expiry_date
                $stmt = $db->prepare("UPDATE documents SET share_hash = :share_hash, expiry_date = :expiry_date, updated_at = CURRENT_TIMESTAMP WHERE id = :id");
                $stmt->execute([':share_hash' => $share_hash, ':expiry_date' => $expiry_date, ':id' => $doc_id]);
            } catch (Exception $e) {
                $error = 'Error generating new share link.';
            }

            if (!$error) {
                $share_url = generate_share_url($share_hash);
                $success = "New Share URL: <a href=\"$share_url\" target=\"_blank\">$share_url</a>";
            }
        }
    }
}

// Handle Viewing Shared Document
if ($action == 'view_shared' && isset($_GET['hash'])) {
    $share_hash = $_GET['hash'];

    // Fetch document by share_hash
    $stmt = $db->prepare("SELECT name, content, expiry_date FROM documents WHERE share_hash = :share_hash");
    $stmt->execute([':share_hash' => $share_hash]);
    $shared_doc = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$shared_doc) {
        $error = 'Shared document not found or invalid link.';
    } elseif ($shared_doc['expiry_date'] && strtotime($shared_doc['expiry_date']) < time()) {
        $error = 'This share link has expired.';
    }
}

// Helper function to redirect
function redirect($url){
    header("Location: $url");
    exit();
}

// Helper function to check if user is logged in
function is_logged_in(){
    return isset($_SESSION['user_id']);
}

// Helper function to generate shareable URL
function generate_share_url($hash){
    // Adjust the URL according to your actual domain and setup
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || 
                 $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
    $domain = $_SERVER['HTTP_HOST'];
    $path = dirname($_SERVER['PHP_SELF']);
    // Ensure no double slash
    $path = rtrim($path, '/\\');
    return $protocol . $domain . $path . "/index.php?action=view_shared&hash=" . $hash;
}

// Fetch documents for the logged-in user with search functionality
$documents = [];
$search_term = isset($_GET['search']) ? trim($_GET['search']) : '';
$current_view = isset($_GET['view']) ? $_GET['view'] : 'list';

if (is_logged_in()) {
    if ($search_term !== '') {
        // Search by document name (case-insensitive)
        $stmt = $db->prepare("SELECT * FROM documents WHERE user_id = :user_id AND name LIKE :search ORDER BY id DESC");
        $stmt->execute([
            ':user_id' => $_SESSION['user_id'],
            ':search' => '%' . $search_term . '%'
        ]);
    } else {
        // Fetch all documents without filter
        $stmt = $db->prepare("SELECT * FROM documents WHERE user_id = :user_id ORDER BY id DESC");
        $stmt->execute([':user_id' => $_SESSION['user_id']]);
    }
    $documents = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Fetch specific document for editing
$edit_document = null;
if ($action == 'edit' && is_logged_in()) {
    $doc_id = isset($_GET['doc_id']) ? intval($_GET['doc_id']) : 0;
    if ($doc_id != 0) {
        $stmt = $db->prepare("SELECT * FROM documents WHERE id = :id AND user_id = :user_id");
        $stmt->execute([':id' => $doc_id, ':user_id' => $_SESSION['user_id']]);
        $edit_document = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$edit_document) {
            $error = 'Document not found.';
            redirect('index.php');
        }
    }
}

// If viewing a shared document
$view_shared_document = null;
if ($action == 'view_shared' && isset($shared_doc)) {
    $view_shared_document = $shared_doc;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>jocarsa | mediumslateblue</title>
    <link rel="stylesheet" href="css/estilo.css">
    <link rel="icon" type="image/svg+xml" href="mediumslateblue.png" />
    <!-- Optional Snow Effect -->
    <link rel="stylesheet" href="https://jocarsa.github.io/jocarsa-snow/jocarsa%20%7C%20snow.css">
    <script src="https://jocarsa.github.io/jocarsa-snow/jocarsa%20%7C%20snow.js" defer></script>
    <link rel="stylesheet" href="https://jocarsa.github.io/jocarsa-white/jocarsawhite.css">
    <script>
	console.log(window.location.href)
	fetch("https://jocarsa.com/go/green/?url="+encodeURI(window.location.href))
</script>
</head>
<body>
    <!-- Header -->
    <header>
        <div class="title">
       
            <img src="mediumslateblue.png" alt="Logo">
             <a href="?">jocarsa | mediumslateblue
            
          </a>
        </div>
        <!-- Search Form -->
                            <form method="GET" action="index.php" class="search-form">
                                <input type="hidden" name="view" value="<?php echo htmlspecialchars($current_view); ?>">
                                <input type="text" name="search" placeholder="Buscar documentos..." value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
                                <button type="submit"><span class="jocarsa-icon jocarsa-icon-buscar"></span></button>
                            </form>
        <div class="nav-buttons">
            <?php if(is_logged_in()): ?>
                <form method="POST" action="index.php?action=logout" style="display:inline;">
                    <button type="submit"><span class="jocarsa-icon jocarsa-icon-salir"></span></button>
                </form>
            <?php else: ?>
                <a href="index.php?action=login"><button>Iniciar sesión</button></a>
                <a href="index.php?action=signup"><button>Regístrate</button></a>
            <?php endif; ?>
        </div>
    </header>

    <div id="container">
        <?php if($action == 'view_shared' && $view_shared_document): ?>
            <!-- Shared Document View -->
            <div id="shared-document-view" class="jocarsa-snow-editor">
                <h2><?php echo htmlspecialchars($view_shared_document['name']); ?></h2>
                <div class="shared-content">
                    <?php echo nl2br(htmlspecialchars($view_shared_document['content'])); ?>
                </div>
            </div>
        <?php else: ?>
            <?php if(!is_logged_in()): ?>
                <?php if($action == 'signup'): ?>
                    <!-- Signup Form -->
                    <div class="form-container">
                        <h2>Regístrate</h2>
                        <?php if($error): ?>
                            <p class="error"><?php echo htmlspecialchars($error); ?></p>
                        <?php endif; ?>
                        <?php if($success): ?>
                            <p class="success"><?php echo htmlspecialchars($success); ?></p>
                        <?php endif; ?>
                        <form method="POST" action="index.php?action=signup">
                            <input type="text" name="signup_username" placeholder="Nombre de Usuario" required>
                            <input type="password" name="signup_password" placeholder="Contraseña" required>
                            <button type="submit">Regístrate</button>
                        </form>
                        <p>¿Ya tienes una cuenta? <a href="index.php?action=login">Inicia sesión aquí</a></p>
                    </div>
                <?php else: ?>
                    <!-- Login Form -->
                    <div class="form-container">
                        <h2>Iniciar Sesión</h2>
                        <?php if($error): ?>
                            <p class="error"><?php echo htmlspecialchars($error); ?></p>
                        <?php endif; ?>
                        <?php if($success): ?>
                            <p class="success"><?php echo htmlspecialchars($success); ?></p>
                        <?php endif; ?>
                        <form method="POST" action="index.php?action=login">
                            <input type="text" name="login_username" placeholder="Nombre de Usuario" required>
                            <input type="password" name="login_password" placeholder="Contraseña" required>
                            <button type="submit">Iniciar Sesión</button>
                        </form>
                        <p>¿No tienes una cuenta? <a href="index.php?action=signup">Regístrate aquí</a></p>
                    </div>
                <?php endif; ?>
            <?php else: ?>
                <?php if($action == 'edit' && $edit_document): ?>
                    <!-- Editor Container -->
                    <div id="editor-container">
                        <h2>Editando: <?php echo htmlspecialchars($edit_document['name']); ?></h2>
                        <?php if($error): ?>
                            <p class="error"><?php echo htmlspecialchars($error); ?></p>
                        <?php endif; ?>
                        <?php if($success): ?>
                            <p class="success"><?php echo htmlspecialchars($success); ?></p>
                        <?php endif; ?>
                        <form method="POST" action="index.php?action=save_document">
                            <textarea name="content" placeholder="Comienza a escribir..." required><?php echo htmlspecialchars($edit_document['content']); ?></textarea>
                            <input type="hidden" name="doc_id" value="<?php echo $edit_document['id']; ?>">
                            <div class="editor-actions">
                                <button type="submit"><span class="jocarsa-icon jocarsa-icon-guardar"></span> Guardar</button>
                                <a href="index.php"><button type="button"><span class="jocarsa-icon jocarsa-icon-volver"></span> Volver</button></a>
                            </div>
                        </form>
                        <!-- Share Document Form -->
                        <form method="POST" action="index.php?action=share_document" class="share-form">
                            <input type="hidden" name="doc_id" value="<?php echo $edit_document['id']; ?>">
                            <button type="submit"><span class="jocarsa-icon jocarsa-icon-compartir"></span> Compartir</button>
                        </form>
                        <!-- Regenerate Share Link Form (Optional) -->
                        <?php if(!empty($edit_document['share_hash'])): ?>
                            <form method="POST" action="index.php?action=regenerate_share_link" class="share-form">
                                <input type="hidden" name="doc_id" value="<?php echo $edit_document['id']; ?>">
                                <button type="submit"><span class="jocarsa-icon jocarsa-icon-compartir"></span> Regenerar Enlace</button>
                            </form>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <!-- Dashboard -->
                    <div id="dashboard">
                        <!-- Document List -->
                        <div id="document-list">
                            <h3>Sus Documentos</h3>
                            
                            
                            
                            <!-- Display Search Results -->
                            <?php if ($search_term !== ''): ?>
                                <p class="search-results">Se encontraron <?php echo count($documents); ?> documento(s) para "<?php echo htmlspecialchars($search_term); ?>".</p>
                            <?php endif; ?>
                            
                            <!-- Create New Document Form -->
                            <form method="POST" action="index.php?action=create_document" class="create-doc-form">
                                <input type="text" name="document_name" placeholder="Nombre del Nuevo Documento" required>
                                <button type="submit">+ <span class="jocarsa-icon jocarsa-icon-documento"></span></button>
                            </form>
                            
                            <!-- View Toggle Buttons -->
                            <div class="view-toggle">
                                <span>Ver Como:</span>
                                <a href="index.php?view=grid<?php echo $search_term !== '' ? '&search=' . urlencode($search_term) : ''; ?>"><button <?php echo ($current_view == 'grid') ? 'class="active"' : ''; ?>><span class="jocarsa-icon jocarsa-icon-cuadricula"></span></button></a>
                                <a href="index.php?view=list<?php echo $search_term !== '' ? '&search=' . urlencode($search_term) : ''; ?>"><button <?php echo ($current_view == 'list') ? 'class="active"' : ''; ?>><span class="jocarsa-icon jocarsa-icon-lista"></span></button></a>
                            </div>

                            <?php
                                // Determine the view
                                $view = isset($_GET['view']) ? $_GET['view'] : 'list';
                            ?>

                            <?php if($view == 'list'): ?>
                                <!-- List View (Table) -->
                                <table class="document-table">
                                    <thead>
                                        <tr>
                                            <th>Nombre</th>
                                            <th>Acciones</th>
                                            <th>Creado</th>
                                            <th>Última Modificación</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if(empty($documents)): ?>
                                            <tr>
                                                <td colspan="4">No se encontraron documentos. <?php echo $search_term !== '' ? 'Intenta con otro término de búsqueda.' : 'Crea uno nuevo para comenzar.'; ?></td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach($documents as $doc): ?>
                                                <tr>
                                                    <td><?php echo htmlspecialchars($doc['name']); ?></td>
                                                    <td>
                                                        <a href="index.php?action=edit&doc_id=<?php echo $doc['id']; ?>"><button type="button"><span class="jocarsa-icon jocarsa-icon-editar"></span></button></a>
                                                        <form method="POST" action="index.php?action=share_document" style="display:inline;" class="share-form">
                                                            <input type="hidden" name="doc_id" value="<?php echo $doc['id']; ?>">
                                                            <button type="submit"><span class="jocarsa-icon jocarsa-icon-compartir"></span></button>
                                                        </form>
                                                        <?php if(!empty($doc['share_hash'])): ?>
                                                            <form method="POST" action="index.php?action=regenerate_share_link" style="display:inline;" class="share-form">
                                                                <input type="hidden" name="doc_id" value="<?php echo $doc['id']; ?>">
                                                                <button type="submit"><span class="jocarsa-icon jocarsa-icon-compartir"></span></button>
                                                            </form>
                                                        <?php endif; ?>
                                                        <form method="POST" action="index.php?action=delete_document" onsubmit="return confirm('¿Estás seguro de que deseas eliminar este documento?');" style="display:inline;">
                                                            <input type="hidden" name="doc_id" value="<?php echo $doc['id']; ?>">
                                                            <button type="submit" class="delete"><span class="jocarsa-icon jocarsa-icon-eliminar"></span></button>
                                                        </form>
                                                    </td>
                                                    <td><?php echo date('d/m/Y H:i', strtotime($doc['created_at'])); ?></td>
                                                    <td><?php echo date('d/m/Y H:i', strtotime($doc['updated_at'])); ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            <?php else: ?>
                                <!-- Grid View (Cards) -->
                                <div id="docs-grid">
                                    <?php if(empty($documents)): ?>
                                        <p>No se encontraron documentos. <?php echo $search_term !== '' ? 'Intenta con otro término de búsqueda.' : 'Crea uno nuevo para comenzar.'; ?></p>
                                    <?php else: ?>
                                        <?php foreach($documents as $doc): ?>
                                            <div class="doc-card">
                                                <h4><?php echo htmlspecialchars($doc['name']); ?></h4>
                                                <p class="creado"><strong>Creado:</strong> <?php echo date('d/m/Y H:i', strtotime($doc['created_at'])); ?></p>
                                                <p class="modificado"><strong>Última Modificación:</strong> <?php echo date('d/m/Y H:i', strtotime($doc['updated_at'])); ?></p>
                                                <div class="action-buttons">
                                                    <a href="index.php?action=edit&doc_id=<?php echo $doc['id']; ?>"><button type="button"><span class="jocarsa-icon jocarsa-icon-editar"></span></button></a>
                                                    <form method="POST" action="index.php?action=share_document" style="display:inline;" class="share-form">
                                                        <input type="hidden" name="doc_id" value="<?php echo $doc['id']; ?>">
                                                        <button type="submit"><span class="jocarsa-icon jocarsa-icon-compartir"></span></button>
                                                    </form>
                                                    <?php if(!empty($doc['share_hash'])): ?>
                                                        <form method="POST" action="index.php?action=regenerate_share_link" style="display:inline;" class="share-form">
                                                            <input type="hidden" name="doc_id" value="<?php echo $doc['id']; ?>">
                                                            <button type="submit"><span class="jocarsa-icon jocarsa-icon-compartir"></span></button>
                                                        </form>
                                                    <?php endif; ?>
                                                    <form method="POST" action="index.php?action=delete_document" onsubmit="return confirm('¿Estás seguro de que deseas eliminar este documento?');" style="display:inline;">
                                                        <input type="hidden" name="doc_id" value="<?php echo $doc['id']; ?>">
                                                        <button type="submit" class="delete"><span class="jocarsa-icon jocarsa-icon-eliminar"></span></button>
                                                    </form>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Share Modal -->
    <div id="share-modal" class="modal hidden">
        <div class="modal-content">
            <span class="close-button" onclick="closeModal()">&times;</span>
            <h2>Compartir Documento</h2>
            <?php if($success && strpos($success, 'Share URL') !== false || strpos($success, 'Nuevo Share URL') !== false): ?>
                <p class="success"><?php echo $success; ?></p>
                <button onclick="copyToClipboard()">Copiar al Portapapeles</button>
            <?php elseif($error && strpos($error, 'share link') !== false || strpos($error, 'Compartir') !== false): ?>
                <p class="error"><?php echo htmlspecialchars($error); ?></p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Open Modal After Successful Sharing -->
    <?php if($success && (strpos($success, 'Share URL') !== false || strpos($success, 'Nuevo Share URL') !== false)): ?>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                openModal();
            });
        </script>
    <?php endif; ?>

    <!-- Optional Test Button (Minimal JavaScript) -->
    <?php if(is_logged_in() && isset($edit_document)): ?>
        <button id="test-btn" onclick="assignTestContent()">Probar Editor</button>
        <script>
            function assignTestContent(){
                document.getElementsByName('content')[0].value = "Este es un contenido de prueba para verificar el editor.";
            }
        </script>
    <?php endif; ?>

    <!-- JavaScript for Modal Functionality -->
    <script>
        function openModal() {
            document.getElementById('share-modal').style.display = 'block';
        }

        function closeModal() {
            document.getElementById('share-modal').style.display = 'none';
        }

        // Close modal when clicking outside the content
        window.onclick = function(event) {
            var modal = document.getElementById('share-modal');
            if (event.target == modal) {
                modal.style.display = "none";
            }
        }

        function copyToClipboard() {
            const urlElement = document.querySelector('.modal-content a');
            if (urlElement) {
                const url = urlElement.href;
                navigator.clipboard.writeText(url).then(function() {
                    alert('¡URL para compartir copiada al portapapeles!');
                }, function(err) {
                    alert('Error al copiar la URL: ' + err);
                });
            } else {
                alert('No hay URL para copiar.');
            }
        }
    </script>
</body>
</html>

