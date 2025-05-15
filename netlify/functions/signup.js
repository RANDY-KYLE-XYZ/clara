const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');

// Database connection URI
const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME;

exports.handler = async (event, context) => {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ message: 'Method not allowed' })
    };
  }

  try {
    const { email, username, password, agreedToTerms } = JSON.parse(event.body);
    
    // Validate input
    if (!email || !username || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'All fields are required' })
      };
    }

    if (!agreedToTerms) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'You must agree to the terms' })
      };
    }

    if (password.length < 8) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Password must be at least 8 characters' })
      };
    }

    const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    await client.connect();
    const db = client.db(dbName);
    const users = db.collection('users');

    // Check if email or username already exists
    const existingUser = await users.findOne({ 
      $or: [
        { email },
        { username }
      ]
    });

    if (existingUser) {
      await client.close();
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Email or username already exists' })
      };
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = {
      email,
      username,
      password: hashedPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
      verified: false,
      role: 'user'
    };

    const result = await users.insertOne(newUser);
    await client.close();

    return {
      statusCode: 201,
      body: JSON.stringify({ 
        message: 'User created successfully',
        userId: result.insertedId
      })
    };

  } catch (error) {
    console.error('Signup error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error' })
    };
  }
};