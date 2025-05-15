const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
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
    const { token } = JSON.parse(event.body);
    
    if (!token) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Token is required' })
      };
    }

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, picture, sub } = payload;

    const mongoClient = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
    await mongoClient.connect();
    const db = mongoClient.db(dbName);
    const users = db.collection('users');

    // Check if user exists
    let user = await users.findOne({ email });

    if (!user) {
      // Create new user
      const newUser = {
        email,
        username: name.toLowerCase().replace(/\s+/g, '_'),
        googleId: sub,
        avatar: picture,
        createdAt: new Date(),
        updatedAt: new Date(),
        verified: true,
        role: 'user'
      };

      const result = await users.insertOne(newUser);
      user = { ...newUser, _id: result.insertedId };
    }

    // Create JWT token
    const jwtToken = jwt.sign(
      { userId: user._id, username: user.username, email: user.email },
      jwtSecret,
      { expiresIn: '7d' }
    );

    await mongoClient.close();

    return {
      statusCode: 200,
      body: JSON.stringify({ 
        token: jwtToken,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          avatar: user.avatar
        }
      })
    };

  } catch (error) {
    console.error('Google auth error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error' })
    };
  }
};