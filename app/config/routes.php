<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');
/**
 * ------------------------------------------------------------------
 * LavaLust - an opensource lightweight PHP MVC Framework
 * ------------------------------------------------------------------
 *
 * MIT License
 *
 * Copyright (c) 2020 Ronald M. Marasigan
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @package LavaLust
 * @author Ronald M. Marasigan <ronald.marasigan@yahoo.com>
 * @since Version 1
 * @link https://github.com/ronmarasigan/LavaLust
 * @license https://opensource.org/licenses/MIT MIT License
 */

/*
| -------------------------------------------------------------------
| URI ROUTING
| -------------------------------------------------------------------
| Here is where you can register web routes for your application.
|
|
*/
/** @var object $router **/

//$router->get('/', 'Welcome::index');

$router->post('create', 'AuthController::register');

$router->post('login', 'AuthController::login');

$router->get('profile', 'AuthController::profile');

$router->get('list', 'AuthController::list_users');

$router->put('update/{id}', 'AuthController::update');

$router->delete('delete/{id}', 'AuthController::delete');

$router->post('refresh', 'AuthController::refresh_token');

$router->post('logout', 'AuthController::logout');


$router->options('create', 'AuthController::options');

$router->options('login', 'AuthController::options');

$router->options('profile', 'AuthController::options');

$router->options('list', 'AuthController::options');

$router->options('update/{id}', 'AuthController::options');

$router->options('delete/{id}', 'AuthController::options');

$router->options('refresh', 'AuthController::options');

$router->options('logout', 'AuthController::options');




$router->get(
    'products',
    'ProductsController::index'
);

$router->get(
    'products/{id}',
    'ProductsController::show'
);

$router->post(
    'products',
    'ProductsController::create'
);

$router->put(
    'products/{id}',
    'ProductsController::update'
);

$router->patch(
    'products/{id}',
    'ProductsController::update'
);

$router->delete(
    'products/{id}',
    'ProductsController::delete'
);


$router->options(
    'products',
    'AuthController::options'
);

$router->options(
    'products/{id}',
    'AuthController::options'
);



$router->get(
    'create-migration/{migration_class}',
    'MigrationController::create_migration'
);

$router->get(
    'migrate',
    'MigrationController::migrate'
);

$router->get(
    'rollback',
    'MigrationController::rollback'
);

$router->get(
    'rollback-all',
    'MigrationController::rollback_all'
);


$router->get(
    'migration-refresh',
    'MigrationController::refresh'
);

$router->get(
    'status',
    'MigrationController::status'
);

