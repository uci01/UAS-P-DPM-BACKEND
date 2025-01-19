const jwt = require('jsonwebtoken');

const authMiddleware = async (req, res, next) => {
    const authHeader = req.header('Authorization');
    console.log('Authorization Header:', authHeader); // Log untuk memeriksa header Authorization

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error('No token or improper format in Authorization header');
        return res.status(401).json({ 
            message: 'No token, authorization denied', 
            hint: 'Ensure Authorization header contains Bearer token' 
        });
    }

    const token = authHeader.split(' ')[1];
    console.log('Extracted Token:', token); // Log untuk memeriksa token yang diambil

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded Token Payload:', decoded); // Log payload token yang telah diverifikasi
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            console.error('Token expired:', error);
            return res.status(401).json({ 
                message: 'Token expired', 
                hint: 'Please log in again to obtain a new token' 
            });
        }
        console.error('Token verification error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
};

module.exports = authMiddleware;
