import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

const users = [
  {
    id: 1,
    email: 'test@example.com',
    password: '$2a$10$E0sO6dYFb.1cK0z8sQj1Ue9QfKd0uW7vXr8bS6yYz5X9vL3aBcD4eF7g', // "password"
    name: 'Test User',
    tokens: 100
  }
];

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { userId: user.id, email: user.email, name: user.name }, 
    process.env.JWT_SECRET, 
    { expiresIn: '1d' }
  );

  res.setHeader('Set-Cookie', cookie.serialize('authToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'strict',
    maxAge: 86400, // 1 day
    path: '/'
  }));

  res.status(200).json({ 
    userId: user.id, 
    name: user.name,
    tokens: user.tokens
  });
}
