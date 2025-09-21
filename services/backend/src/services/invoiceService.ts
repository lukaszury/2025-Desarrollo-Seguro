// src/services/invoiceService.ts
import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface InvoiceRow {
  id: string;
  userId: string;
  amount: number;
  dueDate: Date;
  status: string;
}

class InvoiceService {
  static async list( userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId: userId });
    
    // VULNERABILIDAD: Concatenación directa de parámetros en consulta SQL
    // Esto permite inyección SQL ya que los parámetros se insertan sin validación
    // if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");
    
    // SOLUCIÓN: Validar operadores y usar parámetros preparados
    if (status) {
      // Whitelist de operadores permitidos para prevenir inyección
      const allowedOperators = ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'NOT LIKE'];
      
      if (!operator || !allowedOperators.includes(operator.toUpperCase())) {
        throw new Error('Operador no válido. Operadores permitidos: ' + allowedOperators.join(', '));
      }
      
      // Validar que el status contenga solo caracteres seguros
      if (!/^[a-zA-Z0-9_\s-]+$/.test(status)) {
        throw new Error('Status contiene caracteres no válidos');
      }
      
      // Usar parámetros preparados en lugar de concatenación de strings
      const normalizedOperator = operator.toUpperCase();
      if (normalizedOperator === 'LIKE' || normalizedOperator === 'NOT LIKE') {
        q = q.andWhere('status', normalizedOperator, `%${status}%`);
      } else {
        q = q.andWhere('status', normalizedOperator, status);
      }
    }
    
    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status} as Invoice
    ));
    return invoices;
  }

  static async setPaymentCard(
    userId: string,
    invoiceId: string,
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {
    // VULNERABILIDAD: Construcción de URL sin validación del host
    // Esto permite SSRF ya que se puede especificar cualquier host
    // const paymentResponse = await axios.post(`http://${paymentBrand}/payments`, {
    
    // SOLUCIÓN: Validar y sanitizar el paymentBrand para prevenir SSRF
    const allowedPaymentBrands = ['visa', 'mastercard', 'amex', 'discover'];
    const normalizedBrand = paymentBrand.toLowerCase().trim();
    
    if (!allowedPaymentBrands.includes(normalizedBrand)) {
      throw new Error('Marca de pago no válida. Marcas permitidas: ' + allowedPaymentBrands.join(', '));
    }
    
    // Validar que no contenga caracteres peligrosos para URLs
    if (!/^[a-zA-Z0-9]+$/.test(normalizedBrand)) {
      throw new Error('Marca de pago contiene caracteres no válidos');
    }
    
    // Construir URL segura usando solo el brand validado
    const paymentUrl = `http://${normalizedBrand}/payments`;
    
    // Configurar timeout y validaciones adicionales
    const axiosConfig = {
      timeout: 5000, // 5 segundos timeout
      maxRedirects: 0, // No seguir redirects
      validateStatus: (status) => status < 400 // Solo aceptar códigos < 400
    };
    
    const paymentResponse = await axios.post(paymentUrl, {
      ccNumber,
      ccv,
      expirationDate
    }, axiosConfig);
    
    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    // Update the invoice status in the database
    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });  
    };
  static async  getInvoice( invoiceId:string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }


  static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const filePath = `/invoices/${pdfName}`;
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    } 

  };

};

export default InvoiceService;
