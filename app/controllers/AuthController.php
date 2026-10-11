<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class AuthController extends Controller
{
    public function __construct()
    {
        parent::__construct();

        $this->call->library('api');
        $this->call->database();
    }

    
    public function login()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        $username = trim($body['username'] ?? '');
        $password = $body['password'] ?? '';

        if ($username === '' || $password === '') {
            $this->api->respond_error(
                'Username and password are required.',
                422
            );
        }

        $stmt = $this->db->raw(
            "SELECT * FROM users
             WHERE (username = ? OR email = ?)
             LIMIT 1",
            [$username, $username]
        );

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $this->api->respond_error(
                'Invalid username or password.',
                401
            );
        }

        if (isset($user['is_active']) && !$user['is_active']) {
            $this->api->respond_error(
                'Account is disabled.',
                403
            );
        }

        $tokens = $this->api->issue_tokens([
            'id'     => $user['id'],
            'role'   => $user['role'] ?? 'user',
            'scopes' => ['read', 'write', 'delete'],
        ]);

        $this->api->respond([
            'message' => 'Login successful.',

            // Useful for frontend apps
            'access_token'  => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
            'token_type'    => $tokens['token_type'],
            'expires_in'    => $tokens['expires_in'],

            // IMPORTANT:
            // API Tester checks data.tokens
            'tokens' => $tokens,

            'user' => [
                'id'       => $user['id'],
                'username' => $user['username'],
                'email'    => $user['email'],
                'role'     => $user['role'] ?? 'user',
            ],
        ], 200);
    }


    
    public function register()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        $username = trim($body['username'] ?? '');
        $email    = trim($body['email'] ?? '');
        $password = $body['password'] ?? '';
        $role     = trim($body['role'] ?? 'user');

        if ($username === '' || $email === '' || $password === '') {
            $this->api->respond_error(
                'Username, email and password are required.',
                422
            );
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->api->respond_error(
                'Invalid email address.',
                422
            );
        }

        if (strlen($password) < 6) {
            $this->api->respond_error(
                'Password must contain at least 6 characters.',
                422
            );
        }

        if (!in_array($role, ['user', 'admin'], true)) {
            $role = 'user';
        }

        $stmt = $this->db->raw(
            "SELECT id
             FROM users
             WHERE username = ? OR email = ?
             LIMIT 1",
            [$username, $email]
        );

        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error(
                'Username or email already exists.',
                409
            );
        }

        $this->db->raw(
            "INSERT INTO users
             (username, email, password, role, is_active, created_at)
             VALUES (?, ?, ?, ?, 1, NOW())",
            [
                $username,
                $email,
                password_hash($password, PASSWORD_DEFAULT),
                $role
            ]
        );

        $this->api->respond([
            'status'  => true,
            'message' => 'User registered successfully.'
        ], 201);
    }


    public function profile()
    {
        $this->api->require_method('GET');

        $auth = $this->api->require_jwt();

        $userId = $auth['sub'] ?? null;

        if (!$userId) {
            $this->api->respond_error(
                'Invalid access token.',
                401
            );
        }

        $stmt = $this->db->raw(
            "SELECT id, username, email, role, is_active, created_at
             FROM users
             WHERE id = ?
             LIMIT 1",
            [$userId]
        );

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error(
                'User not found.',
                404
            );
        }

        $this->api->respond([
            'status'  => true,
            'message' => 'Profile retrieved successfully.',
            'data'    => $user
        ], 200);
    }


   
    public function list_users()
    {
        $this->api->require_method('GET');

        $auth = $this->api->require_jwt();

        if (($auth['role'] ?? '') !== 'admin') {
            $this->api->respond_error(
                'Access denied. Admin privileges required.',
                403
            );
        }

        $stmt = $this->db->raw(
            "SELECT id, username, email, role, is_active, created_at
             FROM users
             ORDER BY id DESC"
        );

        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $this->api->respond([
            'status'  => true,
            'message' => 'Users retrieved successfully.',
            'data'    => $users,
            'total'   => count($users)
        ], 200);
    }


   
    public function update($id)
    {
        $this->api->require_method('PUT');

        $auth = $this->api->require_jwt();

        if (!filter_var($id, FILTER_VALIDATE_INT) || (int)$id < 1) {
            $this->api->respond_error(
                'A valid user ID is required.',
                422
            );
        }

        $stmt = $this->db->raw(
            "SELECT *
             FROM users
             WHERE id = ?
             LIMIT 1",
            [$id]
        );

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error(
                'User not found.',
                404
            );
        }

        $currentUserId = $auth['sub'] ?? null;
        $currentRole   = $auth['role'] ?? 'user';

        // Normal users can only update themselves.
        if (
            $currentRole !== 'admin' &&
            (int)$currentUserId !== (int)$id
        ) {
            $this->api->respond_error(
                'You are not allowed to update this user.',
                403
            );
        }

        $body = $this->api->body();

        $username = trim($body['username'] ?? '');
        $email    = trim($body['email'] ?? '');
        $password = $body['password'] ?? '';
        $role     = trim($body['role'] ?? '');

        // Blank fields keep their old values.
        $newUsername = $username !== ''
            ? $username
            : $user['username'];

        $newEmail = $email !== ''
            ? $email
            : $user['email'];

        $newRole = $role !== ''
            ? $role
            : $user['role'];

        if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $this->api->respond_error(
                'Invalid email address.',
                422
            );
        }

        // Normal users cannot promote themselves.
        if ($currentRole !== 'admin') {
            $newRole = $user['role'];
        }

        if (!in_array($newRole, ['user', 'admin'], true)) {
            $newRole = $user['role'];
        }

        // Prevent duplicate username/email.
        $duplicate = $this->db->raw(
            "SELECT id
             FROM users
             WHERE (username = ? OR email = ?)
             AND id != ?
             LIMIT 1",
            [$newUsername, $newEmail, $id]
        );

        if ($duplicate->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error(
                'Username or email already exists.',
                409
            );
        }

        if ($password !== '') {

            if (strlen($password) < 6) {
                $this->api->respond_error(
                    'Password must contain at least 6 characters.',
                    422
                );
            }

            $this->db->raw(
                "UPDATE users
                 SET username = ?,
                     email = ?,
                     password = ?,
                     role = ?
                 WHERE id = ?",
                [
                    $newUsername,
                    $newEmail,
                    password_hash($password, PASSWORD_DEFAULT),
                    $newRole,
                    $id
                ]
            );

        } else {

            $this->db->raw(
                "UPDATE users
                 SET username = ?,
                     email = ?,
                     role = ?
                 WHERE id = ?",
                [
                    $newUsername,
                    $newEmail,
                    $newRole,
                    $id
                ]
            );
        }

        $this->api->respond([
            'status'  => true,
            'message' => 'User updated successfully.',
            'data' => [
                'id'       => (int)$id,
                'username' => $newUsername,
                'email'    => $newEmail,
                'role'     => $newRole
            ]
        ], 200);
    }


  
    public function delete($id)
    {
        $this->api->require_method('DELETE');

        $auth = $this->api->require_jwt();

        if (!filter_var($id, FILTER_VALIDATE_INT) || (int)$id < 1) {
            $this->api->respond_error(
                'A valid user ID is required.',
                422
            );
        }

        $currentUserId = $auth['sub'] ?? null;
        $currentRole   = $auth['role'] ?? 'user';

        if ($currentRole !== 'admin') {
            $this->api->respond_error(
                'Admin privileges required.',
                403
            );
        }

        // Prevent admin from deleting currently logged-in account.
        if ((int)$currentUserId === (int)$id) {
            $this->api->respond_error(
                'You cannot delete your own account.',
                403
            );
        }

        $stmt = $this->db->raw(
            "SELECT id, username
             FROM users
             WHERE id = ?
             LIMIT 1",
            [$id]
        );

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->api->respond_error(
                'User not found.',
                404
            );
        }

        $this->db->raw(
            "DELETE FROM users WHERE id = ?",
            [$id]
        );

        $this->api->respond([
            'status'  => true,
            'message' => 'User deleted successfully.',
            'data' => [
                'id'       => (int)$id,
                'username' => $user['username']
            ]
        ], 200);
    }


   
    public function refresh_token()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        $refreshToken = $body['refresh_token'] ?? '';

        if ($refreshToken === '') {
            $this->api->respond_error(
                'Refresh token is required.',
                422
            );
        }

        // LavaLust API library handles validation,
        // revocation and generation of new tokens.
        $this->api->refresh_access_token($refreshToken);
    }


   
    public function logout()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        $refreshToken = $body['refresh_token'] ?? '';

        if ($refreshToken !== '') {
            $this->api->revoke_refresh_token($refreshToken);
        }

        $this->api->respond([
            'status'  => true,
            'message' => 'Logged out successfully.'
        ], 200);
    }


    public function options()
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

        $allowedOrigins = [
            'https://api-tester.marasigan.dev',
            'http://localhost:5173',
            'http://localhost:5174',
        ];

        if (in_array($origin, $allowedOrigins, true)) {
            header('Access-Control-Allow-Origin: ' . $origin);
        }

        header('Vary: Origin');
        header(
            'Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS'
        );
        header(
            'Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With'
        );
        header('Access-Control-Max-Age: 86400');

        http_response_code(204);
        exit;
    }
}