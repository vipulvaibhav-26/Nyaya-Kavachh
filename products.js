const express = require('express');
const router = express.Router();
const db = require('../db');

// GET all products
router.get('/', async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM products");
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

module.exports = router;
