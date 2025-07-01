# Complete Backend Development Structure - MVC Pattern with Node.js & MongoDB

## Table of Contents
1. [Project Overview](#project-overview)
2. [Project Structure](#project-structure)
3. [Setup & Installation](#setup--installation)
4. [Environment Configuration](#environment-configuration)
5. [Database Configuration](#database-configuration)
6. [Models Layer](#models-layer)
7. [Controllers Layer](#controllers-layer)
8. [Views/Routes Layer](#viewsroutes-layer)
9. [Middleware](#middleware)
10. [Utilities](#utilities)
11. [Error Handling](#error-handling)
12. [Authentication & Authorization](#authentication--authorization)
13. [API Documentation](#api-documentation)
14. [Testing](#testing)
15. [Deployment](#deployment)

## Project Overview

This is a complete backend application built using the **MVC (Model-View-Controller)** architectural pattern with:
- **Node.js**: Runtime environment
- **Express.js**: Web framework
- **MongoDB**: NoSQL database
- **Mongoose**: ODM for MongoDB

### MVC Architecture Explained

- **Model**: Data layer that handles database operations and business logic
- **View**: Presentation layer (API responses in our case)
- **Controller**: Logic layer that handles HTTP requests and coordinates between Model and View

## Project Structure

```
backend-mvc/
├── src/
│   ├── config/
│   │   ├── database.js
│   │   └── environment.js
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── userController.js
│   │   └── productController.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── errorHandler.js
│   │   └── validation.js
│   ├── models/
│   │   ├── User.js
│   │   └── Product.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── users.js
│   │   └── products.js
│   ├── utils/
│   │   ├── logger.js
│   │   ├── helpers.js
│   │   └── validators.js
│   └── app.js
├── tests/
│   ├── unit/
│   └── integration/
├── docs/
├── .env
├── .gitignore
├── package.json
├── server.js
└── README.md
```

## Setup & Installation

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or cloud instance)
- npm or yarn

### Installation Steps

1. **Initialize the project**
```bash
mkdir backend-mvc
cd backend-mvc
npm init -y
```

2. **Install dependencies**
```bash
# Core dependencies
npm install express mongoose dotenv cors helmet morgan

# Development dependencies
npm install -D nodemon jest supertest

# Authentication & Security
npm install bcryptjs jsonwebtoken express-rate-limit

# Validation & Utilities
npm install joi express-validator
```

3. **Update package.json scripts**
```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "test:watch": "jest --watch"
  }
}
```

## Environment Configuration

### .env file
```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database Configuration
MONGODB_URI=mongodb://localhost:27017/mvc_app
MONGODB_TEST_URI=mongodb://localhost:27017/mvc_app_test

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRE=7d

# Other Configuration
BCRYPT_SALT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### src/config/environment.js
```javascript
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  database: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/mvc_app',
    testUri: process.env.MONGODB_TEST_URI || 'mongodb://localhost:27017/mvc_app_test'
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback-secret',
    expire: process.env.JWT_EXPIRE || '7d'
  },
  
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12
  },
  
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
  }
};

module.exports = config;
```

## Database Configuration

### src/config/database.js
```javascript
const mongoose = require('mongoose');
const config = require('./environment');

class Database {
  constructor() {
    this.connection = null;
  }

  async connect() {
    try {
      const uri = config.nodeEnv === 'test' ? config.database.testUri : config.database.uri;
      
      this.connection = await mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      console.log(`MongoDB Connected: ${this.connection.connection.host}`);
      
      // Handle connection events
      mongoose.connection.on('error', (err) => {
        console.error('MongoDB connection error:', err);
      });

      mongoose.connection.on('disconnected', () => {
        console.log('MongoDB disconnected');
      });

      // Graceful shutdown
      process.on('SIGINT', this.disconnect.bind(this));
      
    } catch (error) {
      console.error('Database connection failed:', error);
      process.exit(1);
    }
  }

  async disconnect() {
    if (this.connection) {
      await mongoose.connection.close();
      console.log('MongoDB connection closed');
    }
  }

  async dropDatabase() {
    if (config.nodeEnv === 'test') {
      await mongoose.connection.dropDatabase();
    }
  }
}

module.exports = new Database();
```

## Models Layer

### src/models/User.js
```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config/environment');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters']
  },
  
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false // Don't include password in queries by default
  },
  
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  
  profile: {
    firstName: {
      type: String,
      trim: true
    },
    lastName: {
      type: String,
      trim: true
    },
    avatar: {
      type: String
    },
    bio: {
      type: String,
      maxlength: [500, 'Bio cannot exceed 500 characters']
    }
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  lastLogin: {
    type: Date
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.profile.firstName} ${this.profile.lastName}`.trim();
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    this.password = await bcrypt.hash(this.password, config.bcrypt.saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Instance method to generate JWT token
userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      userId: this._id,
      email: this.email,
      role: this.role 
    },
    config.jwt.secret,
    { expiresIn: config.jwt.expire }
  );
};

// Static method to find user by credentials
userSchema.statics.findByCredentials = async function(email, password) {
  const user = await this.findOne({ email, isActive: true }).select('+password');
  
  if (!user || !(await user.comparePassword(password))) {
    throw new Error('Invalid credentials');
  }
  
  return user;
};

module.exports = mongoose.model('User', userSchema);
```

### src/models/Product.js
```javascript
const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true,
    maxlength: [100, 'Product name cannot exceed 100 characters']
  },
  
  description: {
    type: String,
    required: [true, 'Product description is required'],
    maxlength: [2000, 'Description cannot exceed 2000 characters']
  },
  
  price: {
    type: Number,
    required: [true, 'Product price is required'],
    min: [0, 'Price cannot be negative']
  },
  
  category: {
    type: String,
    required: [true, 'Product category is required'],
    enum: ['electronics', 'clothing', 'books', 'home', 'sports', 'other']
  },
  
  stock: {
    type: Number,
    required: [true, 'Stock quantity is required'],
    min: [0, 'Stock cannot be negative'],
    default: 0
  },
  
  images: [{
    url: {
      type: String,
      required: true
    },
    alt: {
      type: String,
      default: ''
    }
  }],
  
  specifications: {
    type: Map,
    of: String
  },
  
  ratings: {
    average: {
      type: Number,
      default: 0,
      min: 0,
      max: 5
    },
    count: {
      type: Number,
      default: 0
    }
  },
  
  tags: [{
    type: String,
    trim: true
  }],
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for stock status
productSchema.virtual('stockStatus').get(function() {
  if (this.stock === 0) return 'out-of-stock';
  if (this.stock < 10) return 'low-stock';
  return 'in-stock';
});

// Index for better search performance
productSchema.index({ name: 'text', description: 'text' });
productSchema.index({ category: 1 });
productSchema.index({ price: 1 });
productSchema.index({ 'ratings.average': -1 });

// Static method for search
productSchema.statics.search = function(query, options = {}) {
  const {
    category,
    minPrice,
    maxPrice,
    inStock,
    sortBy = 'createdAt',
    sortOrder = 'desc',
    page = 1,
    limit = 10
  } = options;

  const filter = { isActive: true };
  
  if (query) {
    filter.$text = { $search: query };
  }
  
  if (category) {
    filter.category = category;
  }
  
  if (minPrice !== undefined || maxPrice !== undefined) {
    filter.price = {};
    if (minPrice !== undefined) filter.price.$gte = minPrice;
    if (maxPrice !== undefined) filter.price.$lte = maxPrice;
  }
  
  if (inStock) {
    filter.stock = { $gt: 0 };
  }

  const skip = (page - 1) * limit;
  const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

  return this.find(filter)
    .populate('createdBy', 'username email')
    .sort(sort)
    .skip(skip)
    .limit(limit);
};

module.exports = mongoose.model('Product', productSchema);
```

## Controllers Layer

### src/controllers/authController.js
```javascript
const User = require('../models/User');
const { validationResult } = require('express-validator');
const config = require('../config/environment');

class AuthController {
  // Register new user
  async register(req, res, next) {
    try {
      // Check validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { username, email, password, profile } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'User already exists with this email or username'
        });
      }

      // Create new user
      const user = new User({
        username,
        email,
        password,
        profile
      });

      await user.save();

      // Generate token
      const token = user.generateAuthToken();

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            profile: user.profile
          },
          token
        }
      });

    } catch (error) {
      next(error);
    }
  }

  // Login user
  async login(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { email, password } = req.body;

      // Find user and check password
      const user = await User.findByCredentials(email, password);

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Generate token
      const token = user.generateAuthToken();

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            profile: user.profile,
            lastLogin: user.lastLogin
          },
          token
        }
      });

    } catch (error) {
      if (error.message === 'Invalid credentials') {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
      }
      next(error);
    }
  }

  // Get current user profile
  async getProfile(req, res, next) {
    try {
      const user = await User.findById(req.user.userId);
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      res.json({
        success: true,
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            profile: user.profile,
            fullName: user.fullName,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
          }
        }
      });

    } catch (error) {
      next(error);
    }
  }

  // Update user profile
  async updateProfile(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { profile } = req.body;
      
      const user = await User.findByIdAndUpdate(
        req.user.userId,
        { profile },
        { new: true, runValidators: true }
      );

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            profile: user.profile,
            fullName: user.fullName
          }
        }
      });

    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AuthController();
```

### src/controllers/productController.js
```javascript
const Product = require('../models/Product');
const { validationResult } = require('express-validator');

class ProductController {
  // Get all products with filtering and pagination
  async getAllProducts(req, res, next) {
    try {
      const {
        search,
        category,
        minPrice,
        maxPrice,
        inStock,
        sortBy,
        sortOrder,
        page,
        limit
      } = req.query;

      const options = {
        category,
        minPrice: minPrice ? parseFloat(minPrice) : undefined,
        maxPrice: maxPrice ? parseFloat(maxPrice) : undefined,
        inStock: inStock === 'true',
        sortBy: sortBy || 'createdAt',
        sortOrder: sortOrder || 'desc',
        page: parseInt(page) || 1,
        limit: parseInt(limit) || 10
      };

      const products = await Product.search(search, options);
      const total = await Product.countDocuments({ 
        isActive: true,
        ...(category && { category }),
        ...(search && { $text: { $search: search } })
      });

      res.json({
        success: true,
        data: {
          products,
          pagination: {
            current: options.page,
            total: Math.ceil(total / options.limit),
            count: products.length,
            totalRecords: total
          }
        }
      });

    } catch (error) {
      next(error);
    }
  }

  // Get single product by ID
  async getProductById(req, res, next) {
    try {
      const { id } = req.params;

      const product = await Product.findOne({ _id: id, isActive: true })
        .populate('createdBy', 'username email');

      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }

      res.json({
        success: true,
        data: { product }
      });

    } catch (error) {
      next(error);
    }
  }

  // Create new product
  async createProduct(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const productData = {
        ...req.body,
        createdBy: req.user.userId
      };

      const product = new Product(productData);
      await product.save();

      await product.populate('createdBy', 'username email');

      res.status(201).json({
        success: true,
        message: 'Product created successfully',
        data: { product }
      });

    } catch (error) {
      next(error);
    }
  }

  // Update product
  async updateProduct(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { id } = req.params;
      const updateData = req.body;

      const product = await Product.findOneAndUpdate(
        { _id: id, createdBy: req.user.userId },
        updateData,
        { new: true, runValidators: true }
      ).populate('createdBy', 'username email');

      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found or unauthorized'
        });
      }

      res.json({
        success: true,
        message: 'Product updated successfully',
        data: { product }
      });

    } catch (error) {
      next(error);
    }
  }

  // Delete product (soft delete)
  async deleteProduct(req, res, next) {
    try {
      const { id } = req.params;

      const product = await Product.findOneAndUpdate(
        { _id: id, createdBy: req.user.userId },
        { isActive: false },
        { new: true }
      );

      if (!product) {
        return res.status(404).json({
          success: false,
          message: 'Product not found or unauthorized'
        });
      }

      res.json({
        success: true,
        message: 'Product deleted successfully'
      });

    } catch (error) {
      next(error);
    }
  }
}

module.exports = new ProductController();
```

## Views/Routes Layer

### src/routes/auth.js
```javascript
const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const auth = require('../middleware/auth');

const router = express.Router();

// Validation rules
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  
  body('profile.firstName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters'),
  
  body('profile.lastName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters')
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

const updateProfileValidation = [
  body('profile.firstName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('First name cannot exceed 50 characters'),
  
  body('profile.lastName')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Last name cannot exceed 50 characters'),
  
  body('profile.bio')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Bio cannot exceed 500 characters')
];

// Routes
router.post('/register', registerValidation, authController.register);
router.post('/login', loginValidation, authController.login);
router.get('/profile', auth, authController.getProfile);
router.put('/profile', auth, updateProfileValidation, authController.updateProfile);

module.exports = router;
```

### src/routes/products.js
```javascript
const express = require('express');
const { body, param, query } = require('express-validator');
const productController = require('../controllers/productController');
const auth = require('../middleware/auth');

const router = express.Router();

// Validation rules
const createProductValidation = [
  body('name')
    .trim()
    .notEmpty()
    .withMessage('Product name is required')
    .isLength({ max: 100 })
    .withMessage('Product name cannot exceed 100 characters'),
  
  body('description')
    .trim()
    .notEmpty()
    .withMessage('Product description is required')
    .isLength({ max: 2000 })
    .withMessage('Description cannot exceed 2000 characters'),
  
  body('price')
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number'),
  
  body('category')
    .isIn(['electronics', 'clothing', 'books', 'home', 'sports', 'other'])
    .withMessage('Invalid category'),
  
  body('stock')
    .isInt({ min: 0 })
    .withMessage('Stock must be a non-negative integer'),
  
  body('images')
    .isArray({ min: 1 })
    .withMessage('At least one image is required'),
  
  body('images.*.url')
    .isURL()
    .withMessage('Invalid image URL'),
  
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array')
];

const updateProductValidation = [
  body('name')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Product name cannot be empty')
    .isLength({ max: 100 })
    .withMessage('Product name cannot exceed 100 characters'),
  
  body('description')
    .optional()
    .trim()
    .notEmpty()
    .withMessage('Product description cannot be empty')
    .isLength({ max: 2000 })
    .withMessage('Description cannot exceed 2000 characters'),
  
  body('price')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Price must be a positive number'),
  
  body('category')
    .optional()
    .isIn(['electronics', 'clothing', 'books', 'home', 'sports', 'other'])
    .withMessage('Invalid category'),
  
  body('stock')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Stock must be a non-negative integer')
];

const idValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid product ID')
];

const queryValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  
  query('minPrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Min price must be a positive number'),
  
  query('maxPrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Max price must be a positive number')
];

// Routes
router.get('/', queryValidation, productController.getAllProducts);
router.get('/:id', idValidation, productController.getProductById);
router.post('/', auth, createProductValidation, productController.createProduct);
router.put('/:id', auth, idValidation, updateProductValidation, productController.updateProduct);
router.delete('/:id', auth, idValidation, productController.deleteProduct);

module.exports = router;
```

## Middleware

### src/middleware/auth.js
```javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const config = require('../config/environment');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    const decoded = jwt.verify(token, config.jwt.secret);
    const user = await User.findById(decoded.userId);

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. User not found or inactive.'
      });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token.'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired.'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Server error during authentication.'
    });
  }
};

// Admin authorization middleware
const adminAuth = async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Admin privileges required.'
      });
    }
    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error during authorization.'
    });
  }
};

module.exports = { auth, adminAuth };
```

### src/middleware/errorHandler.js
```javascript
const config = require('../config/environment');

// Custom error class
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Handle MongoDB CastError
const handleCastError = (error) => {
  const message = `Invalid ${error.path}: ${error.value}`;
  return new AppError(message, 400);
};

// Handle MongoDB duplicate key error
const handleDuplicateKeyError = (error) => {
  const field = Object.keys(error.keyValue)[0];
  const value = error.keyValue[field];
  const message = `${field.charAt(0).toUpperCase() + field.slice(1)} '${value}' already exists`;
  return new AppError(message, 409);
};

// Handle MongoDB validation error
const handleValidationError = (error) => {
  const errors = Object.values(error.errors).map(err => err.message);
  const message = `Validation Error: ${errors.join('. ')}`;
  return new AppError(message, 400);
};

// Handle JWT errors
const handleJWTError = () => new AppError('Invalid token', 401);
const handleJWTExpiredError = () => new AppError('Token expired', 401);

// Send error response in development
const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    success: false,
    error: err,
    message: err.message,
    stack: err.stack
  });
};

// Send error response in production
const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      message: err.message
    });
  } else {
    // Programming or other unknown error: don't leak error details
    console.error('ERROR:', err);
    
    res.status(500).json({
      success: false,
      message: 'Something went wrong!'
    });
  }
};

// Global error handling middleware
const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (config.nodeEnv === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    // Handle specific MongoDB errors
    if (error.name === 'CastError') error = handleCastError(error);
    if (error.code === 11000) error = handleDuplicateKeyError(error);
    if (error.name === 'ValidationError') error = handleValidationError(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, res);
  }
};

// Handle unhandled routes
const notFound = (req, res, next) => {
  const error = new AppError(`Route ${req.originalUrl} not found`, 404);
  next(error);
};

module.exports = {
  AppError,
  globalErrorHandler,
  notFound
};
```

### src/middleware/validation.js
```javascript
const rateLimit = require('express-rate-limit');
const config = require('../config/environment');

// Rate limiting middleware
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      message
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// General rate limit
const generalLimiter = createRateLimit(
  config.rateLimit.windowMs,
  config.rateLimit.maxRequests,
  'Too many requests from this IP, please try again later.'
);

// Strict rate limit for auth endpoints
const authLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts
  'Too many authentication attempts, please try again later.'
);

// File upload validation
const validateFileUpload = (req, res, next) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).json({
      success: false,
      message: 'No files were uploaded.'
    });
  }

  const file = req.files.file;
  
  // Check file size (5MB limit)
  const maxSize = 5 * 1024 * 1024; // 5MB
  if (file.size > maxSize) {
    return res.status(400).json({
      success: false,
      message: 'File size cannot exceed 5MB.'
    });
  }

  // Check file type
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
  if (!allowedTypes.includes(file.mimetype)) {
    return res.status(400).json({
      success: false,
      message: 'Only JPEG, JPG, PNG and GIF files are allowed.'
    });
  }

  next();
};

// Sanitize input data
const sanitizeInput = (req, res, next) => {
  // Remove any potentially harmful characters
  const sanitize = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        obj[key] = obj[key].replace(/[<>]/g, '');
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitize(obj[key]);
      }
    }
  };

  if (req.body) sanitize(req.body);
  if (req.query) sanitize(req.query);
  if (req.params) sanitize(req.params);

  next();
};

module.exports = {
  generalLimiter,
  authLimiter,
  validateFileUpload,
  sanitizeInput
};
```

## Utilities

### src/utils/logger.js
```javascript
const fs = require('fs');
const path = require('path');
const config = require('../config/environment');

class Logger {
  constructor() {
    this.logDir = path.join(__dirname, '../../logs');
    this.ensureLogDirectory();
  }

  ensureLogDirectory() {
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
  }

  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    return JSON.stringify({
      timestamp,
      level,
      message,
      ...meta
    }) + '\n';
  }

  writeToFile(filename, content) {
    const filepath = path.join(this.logDir, filename);
    fs.appendFileSync(filepath, content);
  }

  log(level, message, meta = {}) {
    const formattedMessage = this.formatMessage(level, message, meta);
    
    // Always log to console in development
    if (config.nodeEnv === 'development') {
      console.log(formattedMessage.trim());
    }

    // Write to appropriate log file
    this.writeToFile(`${level}.log`, formattedMessage);
    this.writeToFile('combined.log', formattedMessage);
  }

  info(message, meta = {}) {
    this.log('info', message, meta);
  }

  warn(message, meta = {}) {
    this.log('warn', message, meta);
  }

  error(message, meta = {}) {
    this.log('error', message, meta);
  }

  debug(message, meta = {}) {
    if (config.nodeEnv === 'development') {
      this.log('debug', message, meta);
    }
  }
}

module.exports = new Logger();
```

### src/utils/helpers.js
```javascript
const crypto = require('crypto');

// Generate random string
const generateRandomString = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

// Generate random number
const generateRandomNumber = (min = 1000, max = 9999) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

// Format currency
const formatCurrency = (amount, currency = 'USD') => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency
  }).format(amount);
};

// Format date
const formatDate = (date, locale = 'en-US') => {
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(new Date(date));
};

// Slugify string
const slugify = (text) => {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w-]+/g, '')
    .replace(/--+/g, '-')
    .replace(/^-+/, '')
    .replace(/-+$/, '');
};

// Capitalize first letter
const capitalize = (text) => {
  return text.charAt(0).toUpperCase() + text.slice(1);
};

// Deep clone object
const deepClone = (obj) => {
  return JSON.parse(JSON.stringify(obj));
};

// Check if object is empty
const isEmpty = (obj) => {
  return Object.keys(obj).length === 0;
};

// Paginate array
const paginate = (array, page = 1, limit = 10) => {
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  
  return {
    data: array.slice(startIndex, endIndex),
    pagination: {
      current: page,
      total: Math.ceil(array.length / limit),
      count: Math.min(limit, array.length - startIndex),
      totalRecords: array.length
    }
  };
};

// Calculate percentage
const calculatePercentage = (value, total) => {
  return total === 0 ? 0 : Math.round((value / total) * 100);
};

// Generate API response
const apiResponse = (success, message, data = null, statusCode = 200) => {
  const response = {
    success,
    message
  };

  if (data !== null) {
    response.data = data;
  }

  return {
    response,
    statusCode
  };
};

module.exports = {
  generateRandomString,
  generateRandomNumber,
  formatCurrency,
  formatDate,
  slugify,
  capitalize,
  deepClone,
  isEmpty,
  paginate,
  calculatePercentage,
  apiResponse
};
```

### src/utils/validators.js
```javascript
const mongoose = require('mongoose');

// Validate MongoDB ObjectId
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// Validate email format
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Validate phone number
const isValidPhone = (phone) => {
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  return phoneRegex.test(phone);
};

// Validate URL
const isValidUrl = (url) => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

// Validate password strength
const isStrongPassword = (password) => {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

// Validate date format (YYYY-MM-DD)
const isValidDate = (date) => {
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(date)) return false;
  
  const parsedDate = new Date(date);
  return parsedDate instanceof Date && !isNaN(parsedDate);
};

// Validate credit card number (basic Luhn algorithm)
const isValidCreditCard = (number) => {
  const num = number.replace(/\D/g, '');
  
  if (num.length < 13 || num.length > 19) return false;
  
  let sum = 0;
  let isSecond = false;
  
  for (let i = num.length - 1; i >= 0; i--) {
    let digit = parseInt(num.charAt(i));
    
    if (isSecond) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    isSecond = !isSecond;
  }
  
  return sum % 10 === 0;
};

// Validate file extension
const hasValidExtension = (filename, allowedExtensions) => {
  const ext = filename.split('.').pop().toLowerCase();
  return allowedExtensions.includes(ext);
};

// Sanitize filename
const sanitizeFilename = (filename) => {
  return filename.replace(/[^a-zA-Z0-9.-]/g, '_');
};

module.exports = {
  isValidObjectId,
  isValidEmail,
  isValidPhone,
  isValidUrl,
  isStrongPassword,
  isValidDate,
  isValidCreditCard,
  hasValidExtension,
  sanitizeFilename
};
```

## Main Application Files

### src/app.js
```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const database = require('./config/database');
const config = require('./config/environment');
const logger = require('./utils/logger');

// Import routes
const authRoutes = require('./routes/auth');
const productRoutes = require('./routes/products');

// Import middleware
const { generalLimiter, sanitizeInput } = require('./middleware/validation');
const { globalErrorHandler, notFound } = require('./middleware/errorHandler');

class App {
  constructor() {
    this.app = express();
    this.connectDatabase();
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  async connectDatabase() {
    try {
      await database.connect();
      logger.info('Database connected successfully');
    } catch (error) {
      logger.error('Database connection failed:', error);
      process.exit(1);
    }
  }

  initializeMiddlewares() {
    // Security middleware
    this.app.use(helmet());
    this.app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
      credentials: true
    }));

    // Rate limiting
    this.app.use(generalLimiter);

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Input sanitization
    this.app.use(sanitizeInput);

    // Logging middleware
    if (config.nodeEnv === 'development') {
      this.app.use(morgan('dev'));
    } else {
      this.app.use(morgan('combined', {
        stream: {
          write: (message) => logger.info(message.trim())
        }
      }));
    }

    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        environment: config.nodeEnv
      });
    });
  }

  initializeRoutes() {
    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/products', productRoutes);

    // API documentation route
    this.app.get('/api', (req, res) => {
      res.json({
        success: true,
        message: 'Welcome to MVC Backend API',
        version: '1.0.0',
        endpoints: {
          auth: {
            'POST /api/auth/register': 'Register new user',
            'POST /api/auth/login': 'Login user',
            'GET /api/auth/profile': 'Get user profile',
            'PUT /api/auth/profile': 'Update user profile'
          },
          products: {
            'GET /api/products': 'Get all products',
            'GET /api/products/:id': 'Get product by ID',
            'POST /api/products': 'Create new product',
            'PUT /api/products/:id': 'Update product',
            'DELETE /api/products/:id': 'Delete product'
          }
        }
      });
    });
  }

  initializeErrorHandling() {
    // Handle 404 routes
    this.app.use(notFound);

    // Global error handler
    this.app.use(globalErrorHandler);
  }

  getApp() {
    return this.app;
  }
}

module.exports = new App();
```

### server.js
```javascript
const app = require('./src/app');
const config = require('./src/config/environment');
const logger = require('./src/utils/logger');

const server = app.getApp().listen(config.port, () => {
  logger.info(`Server running on port ${config.port} in ${config.nodeEnv} mode`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled Promise Rejection:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
  });
});

module.exports = server;
```

## Testing

### Basic Test Setup

Create `tests/setup.js`:
```javascript
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongoServer;

// Setup before all tests
beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri);
});

// Cleanup after all tests
afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// Clean up after each test
afterEach(async () => {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    const collection = collections[key];
    await collection.deleteMany({});
  }
});
```

### Example Test File - `tests/auth.test.js`:
```javascript
const request = require('supertest');
const app = require('../src/app').getApp();
const User = require('../src/models/User');

describe('Auth Endpoints', () => {
  describe('POST /api/auth/register', () => {
    test('Should register a new user', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password123',
        profile: {
          firstName: 'Test',
          lastName: 'User'
        }
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.token).toBeDefined();
    });

    test('Should not register user with invalid email', async () => {
      const userData = {
        username: 'testuser',
        email: 'invalid-email',
        password: 'Password123'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      const user = new User({
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password123'
      });
      await user.save();
    });

    test('Should login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'Password123'
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
    });

    test('Should not login with invalid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword'
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });
});
```

## API Usage Examples

### Authentication Examples

**Register User:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "Password123",
    "profile": {
      "firstName": "John",
      "lastName": "Doe"
    }
  }'
```

**Login User:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "Password123"
  }'
```

### Product Examples

**Create Product:**
```bash
curl -X POST http://localhost:3000/api/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "Laptop",
    "description": "High-performance laptop",
    "price": 999.99,
    "category": "electronics",
    "stock": 10,
    "images": [
      {"url": "https://example.com/laptop.jpg", "alt": "Laptop"}
    ],
    "tags": ["laptop", "computer", "electronics"]
  }'
```

**Get Products with Filters:**
```bash
curl "http://localhost:3000/api/products?category=electronics&minPrice=500&maxPrice=1500&page=1&limit=10"
```

## Deployment

### Environment Variables for Production

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/production_db
JWT_SECRET=your-super-secure-production-jwt-secret
BCRYPT_SALT_ROUNDS=12
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### PM2 Configuration (`ecosystem.config.js`):

```javascript
module.exports = {
  apps: [{
    name: 'mvc-backend',
    script: 'server.js',
    instances: 'max',
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_file: './logs/combined.log',
    time: true
  }]
};
```

### Docker Setup (`Dockerfile`):

```dockerfile
FROM node:16-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

USER node

CMD ["node", "server.js"]
```

### Docker Compose (`docker-compose.yml`):

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongo:27017/mvc_app
    depends_on:
      - mongo
    restart: unless-stopped

  mongo:
    image: mongo:5.0
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
    restart: unless-stopped

volumes:
  mongo_data:
```

## Best Practices Implemented

1. **Security**: Helmet, CORS, rate limiting, input sanitization, JWT authentication
2. **Error Handling**: Centralized error handling, custom error classes, proper HTTP status codes
3. **Validation**: Input validation using express-validator, schema validation with Mongoose
4. **Logging**: Structured logging with different levels and file output
5. **Database**: Connection pooling, indexing, soft deletes, pagination
6. **Code Organization**: Clear separation of concerns, modular structure
7. **Performance**: Efficient database queries, proper indexing, rate limiting
8. **Testing**: Unit and integration tests with proper test database setup
9. **Documentation**: Comprehensive API documentation and code comments
10. **Deployment**: Production-ready configuration, Docker support, PM2 clustering

This complete MVC backend structure provides a solid foundation for building scalable Node.js applications with MongoDB, following industry best practices and security standards.
