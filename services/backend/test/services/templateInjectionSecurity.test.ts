/**
 * Security Test: Template Injection Mitigation
 * 
 * This test validates that the Template Injection vulnerability has been mitigated
 * in the createUser function by ensuring malicious payloads are rejected.
 * 
 * Vulnerability Description:
 * The vulnerable version (main branch) uses direct string interpolation in templates:
 *   const template = `Hello ${user.first_name} ${user.last_name}`;
 * This allows template injection attacks through malicious user input.
 * 
 * Mitigation:
 * The secure version (practico-2) uses:
 * 1. Input validation with regex patterns
 * 2. Safe template rendering using EJS with explicit data binding
 * 3. Fixed template strings with parameterized substitution
 * 
 * Test Strategy:
 * - Test that malicious template payloads are rejected (mitigation working)
 * - Verify safe content is properly rendered
 */

import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db');
jest.mock('nodemailer');

describe('Security: Template Injection Mitigation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env.SMTP_HOST = 'localhost';
    process.env.SMTP_PORT = '25';
    process.env.SMTP_USER = 'test';
    process.env.SMTP_PASS = 'test';
    process.env.FRONTEND_URL = 'http://localhost:3000';
  });

  /**
   * Test Case 1: Attempt to inject template code via first_name
   * Payload: <%= 7*7 %> should be rejected or sanitized
   */
  it('should reject malicious first_name payload attempting template injection', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: '<%= 7*7 %>', // Attempted template injection
      last_name: 'Last',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    // Should throw error due to invalid name validation
    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  /**
   * Test Case 2: Attempt to inject template code via last_name
   * Payload: <%= global.process.exit() %> should be rejected
   */
  it('should reject malicious last_name payload attempting template injection', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: 'First',
      last_name: '<%= global.process.exit() %>', // Attempted code execution
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    // Should throw error due to invalid name validation
    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  /**
   * Test Case 3: Attempt to inject template code via both fields
   * Payload: <%= %> should be rejected
   */
  it('should reject EJS tags in name fields', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: '<%=', // Incomplete EJS tag
      last_name: '%>',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    // Should throw error due to invalid name validation
    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  /**
   * Test Case 4: Attempt to inject via JavaScript code in names
   */
  it('should reject JavaScript code in name fields', async () => {
    const maliciousUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      password: 'password123',
      first_name: '${global.process.exit()}',
      last_name: 'Last',
      username: 'username'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    
    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance.mockReturnValue(selectChain as any);

    // Should throw error due to invalid name validation
    await expect(AuthService.createUser(maliciousUser)).rejects.toThrow('Invalid name');
  });

  /**
   * Test Case 5: Verify safe input is accepted and properly handled
   */
  it('should accept and safely render valid name fields', async () => {
    const safeUser: User = {
      id: 'user-123',
      email: 'safe@example.com',
      password: 'password123',
      first_name: 'John',
      last_name: 'Doe',
      username: 'johndoe'
    };

    // Mock no existing user
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };

    // Mock bcrypt
    jest.mock('bcryptjs', () => ({
      hash: jest.fn().mockResolvedValue('hashed_password')
    }));

    // Mock database insert
    const insertChain = {
      insert: jest.fn().mockReturnThis(),
      returning: jest.fn()
    };

    const mockedDbInstance = db as jest.MockedFunction<typeof db>;
    mockedDbInstance
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Mock nodemailer
    const nodemailer = require('nodemailer');
    const mockSendMail = jest.fn().mockResolvedValue({ success: true });
    nodemailer.createTransport = jest.fn().mockReturnValue({ sendMail: mockSendMail });

    // Should not throw
    await expect(AuthService.createUser(safeUser)).resolves.not.toThrow();
  });
});

