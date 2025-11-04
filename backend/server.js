/*
  This is your NEW backend server with User Authentication.
  Save this file as 'server.js' in your project folder.
*/

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt'); // For password hashing
const jwt = require('jsonwebtoken'); // For user sessions
require('dotenv').config();

const app = express();

// --- Middleware ---
// Enable CORS for all routes, allowing your frontend to communicate
app.use(cors());
// Parse incoming JSON data (like form submissions)
app.use(express.json());

// --- Environment Variables ---
const MONGODB_URI = process.env.MONGODB_URI;
// You MUST add this JWT_SECRET to your .env file and Render.
// Use a long, random string (e.g., from a password generator)
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 10000;

// --- Database Connection ---
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected successfully.');
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
  });

// --- Mongoose Schemas and Models ---

// 1. User Schema (NEW)
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  username: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true }, // This will store the hashed password
  createdAt: { type: Date, default: Date.now }
});

// 2. Customer Schema (UPDATED)
const customerSchema = new mongoose.Schema({
  // NEW: Link to the user who created this customer
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Customer = mongoose.model('Customer', customerSchema);


// --- Authentication Middleware (NEW) ---
// This function will protect our routes
const authenticateToken = (req, res, next) => {
  // Get the token from the 'Authorization' header
  // It's expected in the format: "Bearer TOKEN_STRING"
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Get just the token part

  if (token == null) {
    // No token provided
    return res.status(401).json({ message: 'Authentication token required.' });
  }

  // Verify the token
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      // Token is invalid or expired
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    
    // Token is valid!
    // Add the user payload (which contains the userId) to the request object
    req.user = user;
    next(); // Proceed to the protected route
  });
};


// --- API Routes ---

// === AUTHENTICATION ROUTES (NEW) ===

// 1. POST /api/auth/register (User Registration)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, username, password } = req.body;

    // --- Validation ---
    if (!fullName || !email || !username || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    
    // Check for duplicate username
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ message: 'Email is already in use.' });
      }
      if (existingUser.username === username) {
        return res.status(400).json({ message: 'Username is already in use.' });
      }
    }

    // --- Hash Password ---
    // A "salt round" of 10 is standard
    const hashedPassword = await bcrypt.hash(password, 10);

    // --- Create and Save New User ---
    const newUser = new User({
      fullName,
      email,
      username,
      password: hashedPassword
    });

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });

  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ message: 'Server error during registration.', error: error.message });
  }
});

// 2. POST /api/auth/login (User Login)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { loginIdentifier, password } = req.body; // loginIdentifier can be username or email

    // --- Validation ---
    if (!loginIdentifier || !password) {
      return res.status(400).json({ message: 'Username/Email and password are required.' });
    }

    // --- Find User ---
    // Find user by either email or username
    const user = await User.findOne({
      $or: [{ email: loginIdentifier }, { username: loginIdentifier }]
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // --- Compare Password ---
    // Use bcrypt to compare the provided password with the stored hash
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // --- Create JWT Token ---
    // User is authenticated! Create a token.
    // The "payload" contains user info to identify them in protected routes.
    const tokenPayload = {
      userId: user._id,
      username: user.username
    };

    // Sign the token with your secret key. It will expire in 1 day.
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' });

    // --- Send Response ---
    res.status(200).json({
      message: 'Login successful!',
      token: token, // This is the token the frontend must save
      user: {
        username: user.username,
        fullName: user.fullName
      }
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: 'Server error during login.', error: error.message });
  }
});


// === CUSTOMER (CRM) ROUTES (NOW PROTECTED) ===
// All these routes will now use our 'authenticateToken' middleware first!

// 1. GET /api/customers (Get all customers *for the logged-in user*)
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    // req.user.userId comes from the authenticateToken middleware
    const customers = await Customer.find({ userId: req.user.userId });
    res.status(200).json(customers);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching customers.', error: error.message });
  }
});

// 2. POST /api/customers (Create a new customer *for the logged-in user*)
app.post('/api/customers', authenticateToken, async (req, res) => {
  try {
    const { name, email, phone } = req.body;
    
    const newCustomer = new Customer({
      userId: req.user.userId, // Link to the logged-in user
      name,
      email,
      phone
    });

    await newCustomer.save();
    res.status(201).json(newCustomer);
  } catch (error) {
    res.status(500).json({ message: 'Error creating customer.', error: error.message });
  }
});

// 3. PUT /api/customers/:id (Update a customer)
app.put('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const { name, email, phone } = req.body;
    const customerId = req.params.id;

    // Find the customer by its ID *and* the logged-in user's ID
    // This ensures a user can't edit another user's customers
    const updatedCustomer = await Customer.findOneAndUpdate(
      { _id: customerId, userId: req.user.userId },
      { name, email, phone },
      { new: true } // Return the updated document
    );

    if (!updatedCustomer) {
      return res.status(404).json({ message: 'Customer not found or you do not have permission.' });
    }
    
    res.status(200).json(updatedCustomer);
  } catch (error) {
    res.status(500).json({ message: 'Error updating customer.', error: error.message });
  }
});

// 4. DELETE /api/customers/:id (Delete a customer)
app.delete('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const customerId = req.params.id;

    // Find and delete the customer by its ID *and* the logged-in user's ID
    const deletedCustomer = await Customer.findOneAndDelete({
      _id: customerId,
      userId: req.user.userId
    });

    if (!deletedCustomer) {
      return res.status(404).json({ message: 'Customer not found or you do not have permission.' });
    }

    res.status(200).json({ message: 'Customer deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting customer.', error: error.message });
  }
});

// --- Server Startup ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

