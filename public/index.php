<?php

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use \Slim\Factory\AppFactory;
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use \Firebase\JWT\ExpiredException;

require '../src/vendor/autoload.php';
$app = new \Slim\App;

// Register users
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if username or password already exists
        $checkSql = "SELECT * FROM users WHERE username = :username OR password = :password";
        $stmt = $conn->prepare($checkSql);
        $hashedPassword = hash('SHA256', $pass);
        $stmt->bindParam(':username', $uname);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Username or password already exists"))));
        } else {
            $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
            $stmt = $conn->prepare($sql);
            $stmt->bindParam(':username', $uname);
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->execute();
            $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
    $conn = null;
    return $response;
});

// User authentication and token generation
$app->post('/user/login', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM users WHERE username = :username AND password = :password";
        $stmt = $conn->prepare($sql);
        $hashedPassword = hash('SHA256', $pass);
        $stmt->bindParam(':username', $uname);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($data) {
            $key = 'server_hack';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600,
                'data' => array(
                    $data['userid']
                )
            ];

            $jwt = JWT::encode($payload, $key, 'HS256');

            $response->getBody()->write(
                json_encode(array("status" => "success", "token" => $jwt, "data" => null))
            );
        } else {
            $response->getBody()->write(
                json_encode(array("status" => "fail", "data" => array("title" => "Authentication failed"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
    return $response;
});

// Middleware to validate the token
function validateToken(Request $request, Response $response, $next) {

    $authHeader = $request->getHeader('Authorization');
    $token = '';

    if (!empty($authHeader)) {
        $token = str_replace('Bearer ', '', $authHeader[0]);
    } else {
        $queryParams = $request->getQueryParams();
        if (isset($queryParams['token'])) {
            $token = $queryParams['token'];
        } else {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "No token provided")));
        }
    }

    $key = 'server_hack';
    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if token is already used
        $checkTokenSql = "SELECT * FROM used_tokens WHERE token = :token";
        $checkTokenStmt = $conn->prepare($checkTokenSql);
        $checkTokenStmt->bindParam(':token', $token);
        $checkTokenStmt->execute();

        if ($checkTokenStmt->rowCount() > 0) {
            return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Token has already been used")));
        } else {
            // Mark the token as used
            $insertTokenSql = "INSERT INTO used_tokens (token) VALUES (:token)";
            $insertTokenStmt = $conn->prepare($insertTokenSql);
            $insertTokenStmt->bindParam(':token', $token);
            $insertTokenStmt->execute();
        }

        return $next($request, $response);
    } catch (ExpiredException $e) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Token has expired")));
    } catch (\Exception $e) {
        return $response->withStatus(401)->write(json_encode(array("status" => "fail", "message" => "Invalid token")));
    }
}

// Adding a new book with token validation
$app->post('/books/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $title = $data->title;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO books (title) VALUES (:title)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->execute();

        $bookid = $conn->lastInsertId();
        
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book added successfully", "bookid" => $bookid)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

// Updating a book
$app->put('/books/update/{id}', function (Request $request, Response $response, array $args) {
    $bookId = $args['id'];
    $data = json_decode($request->getBody());
    $title = $data->title;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE books SET title = :title WHERE bookid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':title', $title);
        $stmt->bindParam(':id', $bookId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book updated successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

// Deleting a book
$app->delete('/books/delete/{id}', function (Request $request, Response $response, array $args) {
    $bookId = $args['id'];

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM books WHERE bookid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $bookId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book deleted successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

// Adding a new author
$app->post('/authors/add', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $name = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "INSERT INTO authors (name) VALUES (:name)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->execute();

        $authorid = $conn->lastInsertId();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author added successfully", "authorid" => $authorid)));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); 

// Updating an author
$app->put('/authors/update/{id}', function (Request $request, Response $response, array $args) {
    $authorId = $args['id'];
    $data = json_decode($request->getBody());
    $name = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE authors SET name = :name WHERE authorid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':name', $name);
        $stmt->bindParam(':id', $authorId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author updated successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken'); 

$app->delete('/authors/delete/{id}', function (Request $request, Response $response, array $args) {
    $bookId = $args['id'];

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM authors WHERE authorid = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $bookId);
        $stmt->execute();

        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Author deleted successfully")));
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
})->add('validateToken');

$app->post('/books_author/add', function (Request $request, Response $response, array $args) { 
    $data = json_decode($request->getBody()); 
    $bookid = $data->bookid;
    $authorid = $data->authorid;

    $servername = "localhost";
    $username = "root"; 
    $password = ""; 
    $dbname = "library"; 

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // 1. Check if bookid exists
        $checkBookSql = "SELECT bookid FROM books WHERE bookid = :bookid";
        $checkBookStmt = $conn->prepare($checkBookSql);
        $checkBookStmt->bindParam(':bookid', $bookid);
        $checkBookStmt->execute();

        if ($checkBookStmt->rowCount() === 0) {
            return $response->withStatus(404)
                            ->getBody()
                            ->write(json_encode(array("status" => "fail", "message" => "Book ID not found")));
        }

        // 2. Check if authorid exists
        $checkAuthorSql = "SELECT authorid FROM authors WHERE authorid = :authorid";
        $checkAuthorStmt = $conn->prepare($checkAuthorSql);
        $checkAuthorStmt->bindParam(':authorid', $authorid);
        $checkAuthorStmt->execute();

        if ($checkAuthorStmt->rowCount() === 0) {
            return $response->withStatus(404)
                            ->getBody()
                            ->write(json_encode(array("status" => "fail", "message" => "Author ID not found")));
        }

        // 3. Insert into books_author table if both bookid and authorid exist
        $sql = "INSERT INTO books_author (bookid, authorid) VALUES (:bookid, :authorid)";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':bookid', $bookid); 
        $stmt->bindParam(':authorid', $authorid); 
        $stmt->execute(); 

        // 4. Get the last inserted collectionid
        $collectionid = $conn->lastInsertId();

        // 5. Display the collectionid in the response
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book-Author entry added successfully", "collectionid" => $collectionid))); 
    } catch (PDOException $e) { 
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));  
    } 

    return $response;  
})->add('validateToken');

$app->delete('/books_author/delete/{collectionid}', function (Request $request, Response $response, array $args) {
    $collectionid = $args['collectionid']; // Get the collectionid from the URL

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Create a new PDO connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the collectionid exists
        $checkSql = "SELECT collectionid FROM books_author WHERE collectionid = :collectionid";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bindParam(':collectionid', $collectionid);
        $checkStmt->execute();

        if ($checkStmt->rowCount() === 0) {
            return $response->withStatus(404)
                            ->getBody()
                            ->write(json_encode(array("status" => "fail", "message" => "Collection ID not found")));
        }

        // Delete the entry from the books_author table
        $sql = "DELETE FROM books_author WHERE collectionid = :collectionid";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':collectionid', $collectionid);
        $stmt->execute();

        // Return a success message
        $response->getBody()->write(json_encode(array("status" => "success", "message" => "Book-Author entry deleted successfully")));
    } catch (PDOException $e) {
        // Return a failure message if something goes wrong
        $response->getBody()->write(json_encode(array("status" => "fail", "message" => $e->getMessage())));
    }

    return $response;
    })->add('validateToken'); // Add token validation middleware


$app->run();
