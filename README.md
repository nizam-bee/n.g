import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

const users = [];

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { name, email, password } = req.body;

  if (users.some(u => u.email === email)) {
    return res.status(400).json({ message: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    name,
    email,
    password: hashedPassword,
    tokens: 100 // Starting tokens
  };

  users.push(newUser);

  const token = jwt.sign(
    { userId: newUser.id, email: newUser.email, name: newUser.name }, 
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

  res.status(201).json({ 
    userId: newUser.id, 
    name: newUser.name,
    tokens: newUser.tokens
  });
}
