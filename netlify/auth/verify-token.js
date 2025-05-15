const jwt = require('jsonwebtoken');

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
        statusCode: 401,
        body: JSON.stringify({ message: 'No token provided' })
      };
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    return {
      statusCode: 200,
      body: JSON.stringify({ 
        valid: true,
        user: decoded
      })
    };

  } catch (error) {
    console.error('Token verification error:', error);
    return {
      statusCode: 401,
      body: JSON.stringify({ 
        valid: false,
        message: 'Invalid token'
      })
    };
  }
};