// knexfile.ts
import type { Knex } from 'knex';
import dotenv from 'dotenv';

dotenv.config();

// VULNERABILIDAD: Credenciales por defecto inseguras hardcodeadas
// Esto permite acceso no autorizado si no se configuran variables de entorno
// user: 'user', password: 'password', database: 'jwt_api'

// SOLUCIÓN: Validar que las variables de entorno estén definidas y sean seguras
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  throw new Error(`Variables de entorno requeridas no definidas: ${missingVars.join(', ')}`);
}

// Validar que las credenciales no sean valores por defecto inseguros
const insecureDefaults = {
  'user': process.env.DB_USER,
  'password': process.env.DB_PASS,
  'admin': process.env.DB_USER,
  'root': process.env.DB_USER,
  'test': process.env.DB_USER
};

for (const [insecure, value] of Object.entries(insecureDefaults)) {
  if (value === insecure) {
    throw new Error(`Credencial insegura detectada: ${insecure}. Use una credencial segura en la variable de entorno correspondiente.`);
  }
}

const config: { [key: string]: Knex.Config } = {
  development: {
    client: 'pg',
    connection: {
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      port: parseInt(process.env.DB_PORT || '5432'),
      // Configuraciones adicionales de seguridad
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    },
    migrations: {
      directory: '../migrations',
    },
    seeds: {
      directory: '../seeds',
    },
    // Configuraciones de pool de conexiones para seguridad
    pool: {
      min: 2,
      max: 10,
      createTimeoutMillis: 30000,
      acquireTimeoutMillis: 30000,
      idleTimeoutMillis: 30000,
      reapIntervalMillis: 1000,
      createRetryIntervalMillis: 100,
    },
  },
};

export default config;
