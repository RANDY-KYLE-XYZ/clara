const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

// Database connection URI
const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME;
const jwtSecret = process.env.JWT_SECRET;

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ message: 'Method not allowed' })
    };
  }

  try {
    const { identifier, password } = JSON.parse(event.body);
    
    // Validate input
    if (!identifier || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Email/username and password are required' })
      };
    }

    const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    await client.connect();
    const db = client.db(dbName);
    const users = db.collection('users');

    // Find user by email or username
    const user = await users.findOne({ 
      $or: [
        { email: identifier },
        { username: identifier }
      ]
    });

    if (!user) {
      await client.close();
      return {
        statusCode: 401,
        body: JSON.stringify({ message: 'Invalid credentials' })
      };
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await client.close();
      return {
        statusCode: 401,
        body: JSON.stringify({ message: 'Invalid credentials' })
      };
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email },
      jwtSecret,
      { expiresIn: '7d' }
    );

    await client.close();

    return {
      statusCode: 200,
      body: JSON.stringify({ 
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email
        }
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error' })
    };
  }
};