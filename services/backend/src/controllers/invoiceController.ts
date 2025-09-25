import { Request, Response, NextFunction } from 'express';
import InvoiceService from '../services/invoiceService';
import { Invoice } from '../types/invoice';

const listInvoices = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const state = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;
    const id   = (req as any).user!.id; 
    const invoices = await InvoiceService.list(id, state,operator);
    res.json(invoices);
  } catch (err) {
    next(err);
  }
};

const setPaymentCard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const paymentBrand = req.body.paymentBrand;
    const ccNumber = req.body.ccNumber;
    const ccv = req.body.ccv;
    const expirationDate = req.body.expirationDate;

    if (!paymentBrand || !ccNumber || !ccv || !expirationDate) {
      return res.status(400).json({ error: 'Missing payment details' });
    }
    const id   = (req as any).user!.id; 
    await InvoiceService.setPaymentCard(
      id,
      invoiceId,
      paymentBrand,
      ccNumber,
      ccv,
      expirationDate
    );

    res.status(200).json({ message: 'Payment successful' });
  } catch (err) {
    next(err);
  }
};

const getInvoicePDF = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const pdfName = req.query.pdfName as string | undefined;
    const userId = (req as any).user!.id;  // MITIGACION: Obtener ID del usuario autenticado (antes no lo requeria)

    if (!pdfName) {
      return res.status(400).json({ error: 'Missing parameter pdfName' });
    }
    
    //MITIGACIÓN: Validar que la factura pertenece al usuario antes de descargar PDF
    //Antes traia el PDF simplemente con su id
    // const pdf = await InvoiceService.getReceipt(invoiceId, pdfName);

    const pdf = await InvoiceService.getReceipt(userId, invoiceId, pdfName);
    // return the pdf as a binary response
    res.setHeader('Content-Type', 'application/pdf');
    res.send(pdf);

  } catch (err) {
    next(err);
  }
};

const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const userId = (req as any).user!.id;  //MITIGACION: Obtener ID del usuario autenticado
    
    //MITIGACION: Validar que la factura pertenece al usuario
    //const invoice = await InvoiceService.getInvoice(invoiceId);
    const invoice = await InvoiceService.getInvoice(userId, invoiceId);
    res.status(200).json(invoice);

  } catch (err) {
    next(err);
  }
};

export default {
  listInvoices,
  setPaymentCard,
  getInvoice,
  getInvoicePDF
};