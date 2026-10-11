<?php

defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class ProductsController extends Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->call->library('api');
        $this->call->database();

        // All product CRUD operations require a valid JWT.
        $this->api->require_jwt();
    }

    public function index()
    {
        $this->api->require_method('GET');

        $stmt = $this->db->raw("SELECT * FROM products ORDER BY id DESC");
        $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $this->api->respond($products);
    }

    public function show($id)
    {
        $this->api->require_method('GET');

        $stmt = $this->db->raw("SELECT * FROM products WHERE id = ? LIMIT 1", [$id]);
        $product = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$product) {
            $this->api->respond_error('Product not found.', 404);
        }

        $this->api->respond($product);
    }

    public function create()
    {
        $this->api->require_method('POST');

        $body = $this->api->body();

        $product_name = $body['product_name'] ?? '';
        $description  = $body['description'] ?? '';
        $price        = $body['price'] ?? '';
        $quantity     = isset($body['quantity']) && $body['quantity'] !== '' ? (int) $body['quantity'] : 0;

        if ($product_name === '' || $price === '') {
            $this->api->respond_error('product_name and price are required.', 422);
        }

        $this->db->raw(
            "INSERT INTO products (product_name, description, price, quantity, created_at) VALUES (?, ?, ?, ?, NOW())",
            [$product_name, $description, $price, $quantity]
        );

        $this->api->respond(['message' => 'Product created successfully.'], 201);
    }

    public function update($id)
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'PUT' && $_SERVER['REQUEST_METHOD'] !== 'PATCH') {
            $this->api->respond_error('Method Not Allowed', 405);
        }

        $stmt = $this->db->raw("SELECT id FROM products WHERE id = ? LIMIT 1", [$id]);

        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('Product not found.', 404);
        }

        $body = $this->api->body();

        $product_name = $body['product_name'] ?? '';
        $description  = $body['description'] ?? '';
        $price        = $body['price'] ?? '';
        $quantity     = isset($body['quantity']) && $body['quantity'] !== '' ? (int) $body['quantity'] : 0;

        if ($product_name === '' || $price === '') {
            $this->api->respond_error('product_name and price are required.', 422);
        }

        $this->db->raw(
            "UPDATE products SET product_name = ?, description = ?, price = ?, quantity = ? WHERE id = ?",
            [$product_name, $description, $price, $quantity, $id]
        );

        $this->api->respond(['message' => 'Product updated successfully.']);
    }

    public function delete($id)
    {
        $this->api->require_method('DELETE');

        $stmt = $this->db->raw("SELECT id FROM products WHERE id = ? LIMIT 1", [$id]);

        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('Product not found.', 404);
        }

        $this->db->raw("DELETE FROM products WHERE id = ?", [$id]);

        $this->api->respond(['message' => 'Product deleted successfully.']);
    }
}
