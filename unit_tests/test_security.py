"""
Security-focused unit tests for the Expense Tracker application
Tests critical security features including rate limiting, file validation, and input sanitization
"""

import unittest
import tempfile
import os
import sys
import json
from io import BytesIO

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, validate_file_upload, sanitize_csv_for_export, validate_expense_data, MAX_FILE_SIZE_BYTES


class SecurityTests(unittest.TestCase):
    """Test security features of the application"""
    
    def setUp(self):
        """Set up test client and test data"""
        self.app = app.test_client()
        self.app.testing = True
        
        # Create a test PDF file
        self.test_pdf_data = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF'
        
        # Create a test CSV file
        self.test_csv_data = b'Date,Description,Amount,Category\n2025-01-01,Test Transaction,100.00,misc'

    def test_file_upload_validation_valid_pdf(self):
        """Test that valid PDF files pass validation"""
        try:
            result = validate_file_upload(self.test_pdf_data, 'test.pdf')
            self.assertTrue(result)
        except ValueError as e:
            self.fail(f"Valid PDF should pass validation: {e}")

    def test_file_upload_validation_invalid_extension(self):
        """Test that files with invalid extensions are rejected"""
        with self.assertRaises(ValueError) as context:
            validate_file_upload(self.test_pdf_data, 'test.exe')
        self.assertIn('Unsupported file type', str(context.exception))

    def test_file_upload_validation_path_traversal(self):
        """Test that path traversal attempts are blocked"""
        with self.assertRaises(ValueError) as context:
            validate_file_upload(self.test_pdf_data, '../../../etc/passwd.pdf')
        self.assertIn('Invalid filename', str(context.exception))

    def test_file_upload_validation_large_file(self):
        """Test that oversized files are rejected"""
        # Create a file larger than the limit
        large_file_data = b'x' * (MAX_FILE_SIZE_BYTES + 1)
        with self.assertRaises(ValueError) as context:
            validate_file_upload(large_file_data, 'large.pdf')
        self.assertIn('File too large', str(context.exception))

    def test_csv_sanitization_formula_injection(self):
        """Test that formula injection attempts are neutralized"""
        malicious_csv = 'Date,Description,Amount,Category\n2025-01-01,=cmd|" /C calc"!A0,100.00,misc\n2025-01-02,+cmd|" /C calc"!A0,200.00,misc\n2025-01-03,-cmd|" /C calc"!A0,300.00,misc\n2025-01-04,@cmd|" /C calc"!A0,400.00,misc'
        
        sanitized_csv = sanitize_csv_for_export(malicious_csv)
        
        # Check that formulas are prefixed with apostrophe
        self.assertIn("'=cmd|", sanitized_csv)
        self.assertIn("'+cmd|", sanitized_csv)
        self.assertIn("'-cmd|", sanitized_csv)
        self.assertIn("'@cmd|", sanitized_csv)

    def test_expense_data_validation_valid(self):
        """Test that valid expense data passes validation"""
        valid_expense = {
            'date': '2025-01-01',
            'description': 'Test expense',
            'amount': '100.00',
            'category': 'misc'
        }
        
        try:
            result = validate_expense_data(valid_expense)
            self.assertEqual(result, valid_expense)
        except ValueError as e:
            self.fail(f"Valid expense should pass validation: {e}")

    def test_expense_data_validation_missing_fields(self):
        """Test that expense data with missing required fields is rejected"""
        invalid_expense = {
            'date': '2025-01-01',
            # Missing description
            'amount': '100.00',
            'category': 'misc'
        }
        
        with self.assertRaises(ValueError) as context:
            validate_expense_data(invalid_expense)
        self.assertIn('Missing required field', str(context.exception))

    def test_expense_data_validation_invalid_date(self):
        """Test that invalid date formats are rejected"""
        invalid_expense = {
            'date': 'invalid-date',
            'description': 'Test expense',
            'amount': '100.00',
            'category': 'misc'
        }
        
        with self.assertRaises(ValueError) as context:
            validate_expense_data(invalid_expense)
        self.assertIn('Invalid date format', str(context.exception))

    def test_expense_data_validation_invalid_amount(self):
        """Test that invalid amounts are rejected"""
        invalid_expense = {
            'date': '2025-01-01',
            'description': 'Test expense',
            'amount': 'invalid',
            'category': 'misc'
        }
        
        with self.assertRaises(ValueError) as context:
            validate_expense_data(invalid_expense)
        self.assertIn('Invalid amount format', str(context.exception))

    def test_expense_data_validation_xss_sanitization(self):
        """Test that XSS attempts in descriptions are sanitized"""
        xss_expense = {
            'date': '2025-01-01',
            'description': '<script>alert("xss")</script>',
            'amount': '100.00',
            'category': 'misc'
        }
        
        result = validate_expense_data(xss_expense)
        self.assertIn('<script>', result['description'])
        self.assertIn('</script>', result['description'])

    def test_rate_limiting_configuration(self):
        """Test that rate limiting configuration is properly loaded"""
        from app import RATE_LIMITS
        self.assertIn('pdf_upload', RATE_LIMITS)
        self.assertIn('ai_processing', RATE_LIMITS)
        self.assertIn('login', RATE_LIMITS)
        self.assertIn('general_api', RATE_LIMITS)

    def test_security_headers_presence(self):
        """Test that security headers are properly configured"""
        with app.test_client() as client:
            response = client.get('/')
            # Check for some security headers
            self.assertIn('X-Content-Type-Options', response.headers)
            self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff')
            self.assertIn('X-Frame-Options', response.headers)
            self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY')


if __name__ == '__main__':
    unittest.main()
