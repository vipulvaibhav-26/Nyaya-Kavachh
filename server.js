// ============================================
// E-COMMERCE BACKEND API - Node.js + Express + MySQL
// ============================================

// Required dependencies to install:
// npm install express mysql2 bcryptjs jsonwebtoken cors dotenv body-parser express-validator

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

// ============================================
// MIDDLEWARE
// ============================================

// MIDDLEWARE (around line 20)
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500', 'null'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// ============================================
// DATABASE CONNECTION
// ============================================

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'ecommerce_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;

async function initDatabase() {
    try {
        // Create connection without database first
        const connection = await mysql.createConnection({
            host: dbConfig.host,
            user: dbConfig.user,
            password: dbConfig.password
        });

        // Create database if not exists
        await connection.query(`CREATE DATABASE IF NOT EXISTS ${dbConfig.database}`);
        await connection.end();

        // Create pool with database
        pool = mysql.createPool(dbConfig);

        // Create tables
        await createTables();
        console.log('✅ Database initialized successfully');
    } catch (error) {
        console.error('❌ Database initialization error:', error);
        process.exit(1);
    }
}

async function createTables() {
    const connection = await pool.getConnection();
    
    try {
        // Users table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('buyer', 'seller', 'admin') DEFAULT 'buyer',
                phone VARCHAR(20),
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);

        // Products table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS products (
                id INT AUTO_INCREMENT PRIMARY KEY,
                seller_id INT NOT NULL,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                category VARCHAR(100) NOT NULL,
                image_url TEXT,
                stock_quantity INT DEFAULT 0,
                status ENUM('active', 'inactive') DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_category (category),
                INDEX idx_seller (seller_id)
            )
        `);

        // Cart table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS cart (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                UNIQUE KEY unique_user_product (user_id, product_id)
            )
        `);

        // Orders table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                total_amount DECIMAL(10, 2) NOT NULL,
                status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
                shipping_address TEXT NOT NULL,
                payment_method VARCHAR(50),
                payment_status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Order Items table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id)
            )
        `);

        // Reviews table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS reviews (
                id INT AUTO_INCREMENT PRIMARY KEY,
                product_id INT NOT NULL,
                user_id INT NOT NULL,
                rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        console.log('✅ All tables created successfully');
    } finally {
        connection.release();
    }
}

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

function isSeller(req, res, next) {
    if (req.user.role !== 'seller' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    next();
}

// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post('/api/auth/register', [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('role').optional().isIn(['buyer', 'seller']).withMessage('Invalid role')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { name, email, password, role = 'buyer', phone, address } = req.body;

        // Check if user exists
        const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        const [result] = await pool.query(
            'INSERT INTO users (name, email, password, role, phone, address) VALUES (?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, role, phone, address]
        );

        // Generate token
        const token = jwt.sign(
            { id: result.insertId, email, role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: result.insertId, name, email, role }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login
app.post('/api/auth/login', [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, password } = req.body;

        // Get user
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, name, email, role, phone, address, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(users[0]);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// ============================================
// PRODUCT ROUTES
// ============================================

// Get all products (with filters)
app.get('/api/products', async (req, res) => {
    try {
        const { category, search, minPrice, maxPrice, sellerId, limit = 50, offset = 0 } = req.query;

        let query = `
            SELECT p.*, u.name as seller_name, u.email as seller_email
            FROM products p
            JOIN users u ON p.seller_id = u.id
            WHERE p.status = 'active'
        `;
        const params = [];

        if (category) {
            query += ' AND p.category = ?';
            params.push(category);
        }

        if (search) {
            query += ' AND (p.name LIKE ? OR p.description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }

        if (minPrice) {
            query += ' AND p.price >= ?';
            params.push(minPrice);
        }

        if (maxPrice) {
            query += ' AND p.price <= ?';
            params.push(maxPrice);
        }

        if (sellerId) {
            query += ' AND p.seller_id = ?';
            params.push(sellerId);
        }

        query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const [products] = await pool.query(query, params);
        res.json(products);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
    try {
        const [products] = await pool.query(`
            SELECT p.*, u.name as seller_name, u.email as seller_email
            FROM products p
            JOIN users u ON p.seller_id = u.id
            WHERE p.id = ?
        `, [req.params.id]);

        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Get reviews
        const [reviews] = await pool.query(`
            SELECT r.*, u.name as user_name
            FROM reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.product_id = ?
            ORDER BY r.created_at DESC
        `, [req.params.id]);

        res.json({ ...products[0], reviews });
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ error: 'Failed to fetch product' });
    }
});

// Create product (seller only)
app.post('/api/products', authenticateToken, isSeller, [
    body('name').trim().notEmpty().withMessage('Product name is required'),
    body('price').isFloat({ min: 0 }).withMessage('Valid price is required'),
    body('category').trim().notEmpty().withMessage('Category is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { name, description, price, category, image_url, stock_quantity = 0 } = req.body;

        const [result] = await pool.query(
            `INSERT INTO products (seller_id, name, description, price, category, image_url, stock_quantity)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, name, description, price, category, image_url, stock_quantity]
        );

        res.status(201).json({
            message: 'Product created successfully',
            productId: result.insertId
        });
    } catch (error) {
        console.error('Create product error:', error);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

// Update product (seller only)
app.put('/api/products/:id', authenticateToken, isSeller, async (req, res) => {
    try {
        const { name, description, price, category, image_url, stock_quantity, status } = req.body;

        // Check ownership
        const [products] = await pool.query('SELECT seller_id FROM products WHERE id = ?', [req.params.id]);
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        if (products[0].seller_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized to update this product' });
        }

        const updates = [];
        const params = [];

        if (name) { updates.push('name = ?'); params.push(name); }
        if (description) { updates.push('description = ?'); params.push(description); }
        if (price) { updates.push('price = ?'); params.push(price); }
        if (category) { updates.push('category = ?'); params.push(category); }
        if (image_url) { updates.push('image_url = ?'); params.push(image_url); }
        if (stock_quantity !== undefined) { updates.push('stock_quantity = ?'); params.push(stock_quantity); }
        if (status) { updates.push('status = ?'); params.push(status); }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        params.push(req.params.id);

        await pool.query(
            `UPDATE products SET ${updates.join(', ')} WHERE id = ?`,
            params
        );

        res.json({ message: 'Product updated successfully' });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// Delete product (seller only)
app.delete('/api/products/:id', authenticateToken, isSeller, async (req, res) => {
    try {
        const [products] = await pool.query('SELECT seller_id FROM products WHERE id = ?', [req.params.id]);
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        if (products[0].seller_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Not authorized to delete this product' });
        }

        await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// ============================================
// CART ROUTES
// ============================================

// Get cart
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [items] = await pool.query(`
            SELECT c.*, p.name, p.price, p.image_url, p.stock_quantity
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ? AND p.status = 'active'
        `, [req.user.id]);

        const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

        res.json({ items, total });
    } catch (error) {
        console.error('Get cart error:', error);
        res.status(500).json({ error: 'Failed to fetch cart' });
    }
});

// Add to cart
app.post('/api/cart', authenticateToken, [
    body('product_id').isInt().withMessage('Valid product ID is required'),
    body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be at least 1')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { product_id, quantity = 1 } = req.body;

        // Check product exists and has stock
        const [products] = await pool.query('SELECT stock_quantity FROM products WHERE id = ? AND status = "active"', [product_id]);
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found or inactive' });
        }

        await pool.query(`
            INSERT INTO cart (user_id, product_id, quantity)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE quantity = quantity + ?
        `, [req.user.id, product_id, quantity, quantity]);

        res.status(201).json({ message: 'Item added to cart' });
    } catch (error) {
        console.error('Add to cart error:', error);
        res.status(500).json({ error: 'Failed to add to cart' });
    }
});

// Update cart item
app.put('/api/cart/:productId', authenticateToken, [
    body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { quantity } = req.body;

        await pool.query(
            'UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?',
            [quantity, req.user.id, req.params.productId]
        );

        res.json({ message: 'Cart updated' });
    } catch (error) {
        console.error('Update cart error:', error);
        res.status(500).json({ error: 'Failed to update cart' });
    }
});

// Remove from cart
app.delete('/api/cart/:productId', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM cart WHERE user_id = ? AND product_id = ?',
            [req.user.id, req.params.productId]
        );

        res.json({ message: 'Item removed from cart' });
    } catch (error) {
        console.error('Remove from cart error:', error);
        res.status(500).json({ error: 'Failed to remove from cart' });
    }
});

// Clear cart
app.delete('/api/cart', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
        res.json({ message: 'Cart cleared' });
    } catch (error) {
        console.error('Clear cart error:', error);
        res.status(500).json({ error: 'Failed to clear cart' });
    }
});

// ============================================
// ORDER ROUTES
// ============================================

// Create order
app.post('/api/orders', authenticateToken, [
    body('shipping_address').trim().notEmpty().withMessage('Shipping address is required'),
    body('payment_method').trim().notEmpty().withMessage('Payment method is required')
], async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        await connection.beginTransaction();

        const { shipping_address, payment_method } = req.body;

        // Get cart items
        const [cartItems] = await connection.query(`
            SELECT c.*, p.price, p.stock_quantity
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ? AND p.status = 'active'
        `, [req.user.id]);

        if (cartItems.length === 0) {
            await connection.rollback();
            return res.status(400).json({ error: 'Cart is empty' });
        }

        // Check stock
        for (const item of cartItems) {
            if (item.stock_quantity < item.quantity) {
                await connection.rollback();
                return res.status(400).json({ error: `Insufficient stock for product ID ${item.product_id}` });
            }
        }

        // Calculate total
        const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);

        // Create order
        const [orderResult] = await connection.query(
            `INSERT INTO orders (user_id, total_amount, shipping_address, payment_method, payment_status)
             VALUES (?, ?, ?, ?, 'completed')`,
            [req.user.id, total, shipping_address, payment_method]
        );

        const orderId = orderResult.insertId;

        // Create order items
        for (const item of cartItems) {
            await connection.query(
                'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                [orderId, item.product_id, item.quantity, item.price]
            );

            // Update stock
            await connection.query(
                'UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ?',
                [item.quantity, item.product_id]
            );
        }

        // Clear cart
        await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

        await connection.commit();

        res.status(201).json({
            message: 'Order placed successfully',
            orderId,
            total
        });
    } catch (error) {
        await connection.rollback();
        console.error('Create order error:', error);
        res.status(500).json({ error: 'Failed to create order' });
    } finally {
        connection.release();
    }
});

// Get user orders
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.query(`
            SELECT o.*, 
                   COUNT(oi.id) as item_count
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.user_id = ?
            GROUP BY o.id
            ORDER BY o.created_at DESC
        `, [req.user.id]);

        res.json(orders);
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// Get order details
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);

        if (orders.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        const [items] = await pool.query(`
            SELECT oi.*, p.name, p.image_url
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = ?
        `, [req.params.id]);

        res.json({ ...orders[0], items });
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({ error: 'Failed to fetch order' });
    }
});

// ============================================
// SELLER DASHBOARD ROUTES
// ============================================

// Get seller statistics
app.get('/api/seller/stats', authenticateToken, isSeller, async (req, res) => {
    try {
        const [stats] = await pool.query(`
            SELECT 
                COUNT(DISTINCT p.id) as total_products,
                COUNT(DISTINCT o.id) as total_orders,
                COALESCE(SUM(oi.quantity * oi.price), 0) as total_revenue,
                COUNT(DISTINCT CASE WHEN o.status IN ('pending', 'processing') THEN o.id END) as active_orders
            FROM products p
            LEFT JOIN order_items oi ON p.id = oi.product_id
            LEFT JOIN orders o ON oi.order_id = o.id
            WHERE p.seller_id = ?
        `, [req.user.id]);

        res.json(stats[0]);
    } catch (error) {
        console.error('Get seller stats error:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Get seller orders
app.get('/api/seller/orders', authenticateToken, isSeller, async (req, res) => {
    try {
        const [orders] = await pool.query(`
            SELECT DISTINCT o.*, u.name as buyer_name, u.email as buyer_email
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            JOIN users u ON o.user_id = u.id
            WHERE p.seller_id = ?
            ORDER BY o.created_at DESC
        `, [req.user.id]);

        res.json(orders);
    } catch (error) {
        console.error('Get seller orders error:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// ============================================
// REVIEW ROUTES
// ============================================

// Add review
app.post('/api/reviews', authenticateToken, [
    body('product_id').isInt().withMessage('Valid product ID is required'),
    body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
    body('comment').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { product_id, rating, comment } = req.body;

        // Check if user has purchased the product
        const [purchases] = await pool.query(`
            SELECT 1 FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            WHERE o.user_id = ? AND oi.product_id = ? AND o.status = 'delivered'
            LIMIT 1
        `, [req.user.id, product_id]);

        if (purchases.length === 0) {
            return res.status(400).json({ error: 'You can only review products you have purchased' });
        }

        await pool.query(
            'INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
            [product_id, req.user.id, rating, comment]
        );

        res.status(201).json({ message: 'Review added successfully' });
    } catch (error) {
        console.error('Add review error:', error);
        res.status(500).json({ error: 'Failed to add review' });
    }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 5000;

async function startServer() {
    await initDatabase();
    
    app.listen(PORT, () => {
        console.log(`
╔═══════════════════════════════════════╗
║  🚀 E-Commerce API Server Running    ║
║  📡 Port: ${PORT}                      ║
║  🗄️  Database: MySQL                  ║
║  ✅ Status: Active                    ║
╚═══════════════════════════════════════╝
        `);
    });
}

startServer().catch(console.error);

module.exports = app;
