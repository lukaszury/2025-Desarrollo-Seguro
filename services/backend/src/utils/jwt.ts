import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

// Cargar variables de entorno
dotenv.config();

// VULNERABILIDAD: Secret JWT hardcodeado en el código
// Esto permite que cualquier persona con acceso al código genere tokens falsos
// const JWT_SECRET = "secreto_super_seguro";

// SOLUCIÓN: Usar variable de entorno para el secreto JWT
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET no está definido en las variables de entorno');
}

// Validar que el secreto tenga la longitud mínima recomendada
if (JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET debe tener al menos 32 caracteres por seguridad');
}

const generateToken = (userId: string) => {
  return jwt.sign(
    { id: userId }, 
    JWT_SECRET, 
    { expiresIn: '1h' }
  );
};

const verifyToken = (token: string) => {
  return jwt.verify(token, JWT_SECRET);
};

export default {
  generateToken,
  verifyToken
}