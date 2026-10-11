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

        // For frontend applications
        'access_token'  => $tokens['access_token'],
        'refresh_token' => $tokens['refresh_token'],
        'token_type'    => $tokens['token_type'],
        'expires_in'    => $tokens['expires_in'],

        // IMPORTANT:
        // LavaLust API Tester expects data.tokens
        'tokens' => $tokens,

        'user' => [
            'id'       => $user['id'],
            'username' => $user['username'],
            'email'    => $user['email'],
            'role'     => $user['role'] ?? 'user',
        ],
    ], 200);
}

    public function profile()
{
    $auth = $this->api->require_jwt();

    $userId = $auth['sub'] ?? null;

    if (!$userId) {
        $this->api->respond_error('Invalid access token.', 401);
    }

    $stmt = $this->db->raw(
        'SELECT id, username, email, role, created_at
         FROM users
         WHERE id = ?
         LIMIT 1',
        [$userId]
    );

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $this->api->respond_error('User not found.', 404);
    }

    $this->api->respond([
        'status'  => true,
        'message' => 'Profile retrieved successfully.',
        'data'    => $user
    ], 200);
}

    public function register()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        $username = $body['username'] ?? '';
        $email    = $body['email'] ?? '';
        $password = $body['password'] ?? '';
        $role     = $body['role'] ?? 'user';

        if ($username === '' || $email === '' || $password === '') {
            $this->api->respond_error('Username, email and password are required.', 422);
        }

        $stmt = $this->db->raw(
            "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
            [$username, $email]
        );

        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('Username or email already exists.', 409);
        }

        $this->db->raw(
            "INSERT INTO users (username, email, password, role, is_active, created_at) VALUES (?, ?, ?, ?, 1, NOW())",
            [$username, $email, password_hash($password, PASSWORD_DEFAULT), $role]
        );

        $this->api->respond(['message' => 'User registered successfully.'], 201);
    }
    
    public function list()
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

    public function update()
    {
        $this->api->require_method('PUT');

        $auth = $this->api->require_jwt();

        if (($auth['role'] ?? '') !== 'admin') {
            $this->api->respond_error(
                'Access denied. Admin privileges required.',
                403
            );
        }

        $body = $this->api->body();

        $id = $body['id'] ?? null;

        if (!$id || !filter_var($id, FILTER_VALIDATE_INT) || $id < 1) {
            $this->api->respond_error(
                'A valid user ID is required.',
                422
            );
        }

        $stmt = $this->db->raw(
            "SELECT id FROM users WHERE id = ? LIMIT 1",
            [$id]
        );

        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('User not found.', 404);
        }

        $username = trim($body['username'] ?? '');
        $email    = trim($body['email'] ?? '');
        $role     = trim($body['role'] ?? '');
        $password = $body['password'] ?? '';
        $isActive = $body['is_active'] ?? null;

        if (
            $username === '' ||
            $email === '' ||
            $role === ''
        ) {
            $this->api->respond_error(
                'Username, email, and role are required.',
                422
            );
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->api->respond_error(
                'Please provide a valid email address.',
                422
            );
        }

        $allowedRoles = ['admin', 'user'];

        if (!in_array($role, $allowedRoles, true)) {
            $this->api->respond_error('Invalid role.', 422);
        }

        if (
            $isActive !== null &&
            !in_array($isActive, [0, 1, '0', '1', true, false], true)
        ) {
            $this->api->respond_error(
                'is_active must be 0 or 1.',
                422
            );
        }

        $stmt = $this->db->raw(
            "SELECT id FROM users
             WHERE (username = ? OR email = ?)
             AND id != ?
             LIMIT 1",
            [$username, $email, $id]
        );

        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error(
                'Username or email already exists.',
                409
            );
        }

        if ($isActive === null) {
            $stmt = $this->db->raw(
                "SELECT is_active FROM users WHERE id = ?",
                [$id]
            );

            $currentUser = $stmt->fetch(PDO::FETCH_ASSOC);
            $isActive = $currentUser['is_active'];
        }

        $isActive = (int) $isActive;

        if ($password !== '') {
            $this->db->raw(
                "UPDATE users
                 SET username = ?, email = ?, role = ?,
                     password = ?, is_active = ?
                 WHERE id = ?",
                [
                    $username,
                    $email,
                    $role,
                    password_hash($password, PASSWORD_DEFAULT),
                    $isActive,
                    $id
                ]
            );
        } else {
            $this->db->raw(
                "UPDATE users
                 SET username = ?, email = ?, role = ?,
                     is_active = ?
                 WHERE id = ?",
                [$username, $email, $role, $isActive, $id]
            );
        }

        $this->api->respond([
            'status'  => true,
            'message' => 'User updated successfully.'
        ], 200);
    }

    public function delete()
    {
        $this->api->require_method('DELETE');

        $auth = $this->api->require_jwt();

        if (($auth['role'] ?? '') !== 'admin') {
            $this->api->respond_error(
                'Access denied. Admin privileges required.',
                403
            );
        }

        $body = $this->api->body();

        $id = $body['id'] ?? null;

        if (!$id || !filter_var($id, FILTER_VALIDATE_INT) || $id < 1) {
            $this->api->respond_error(
                'A valid user ID is required.',
                422
            );
        }

        $currentUserId = $auth['sub'] ?? null;

        if ((string) $id === (string) $currentUserId) {
            $this->api->respond_error(
                'You cannot delete your own account.',
                403
            );
        }

        $stmt = $this->db->raw(
            "SELECT id FROM users WHERE id = ? LIMIT 1",
            [$id]
        );

        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('User not found.', 404);
        }

        $this->db->raw(
            "DELETE FROM users WHERE id = ?",
            [$id]
        );

        $this->api->respond([
            'status'  => true,
            'message' => 'User deleted successfully.'
        ], 200);
    }


    public function logout()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        if (!empty($body['refresh_token'])) {
            $this->api->revoke_refresh_token($body['refresh_token']);
        }

        $this->api->respond(['message' => 'Logged out successfully.']);
    }
}
