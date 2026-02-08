"""Sample test documents for development and testing."""

SAMPLE_DOCUMENT = b"""
This is a sample confidential document for testing the Encrypted Document Signing Platform.

Document ID: TEST-001
Classification: CONFIDENTIAL
Date: January 20, 2026

Content:
This document demonstrates the end-to-end encryption and digital signature workflow.
When uploaded, this document will be:
1. Encrypted using AES-256-GCM with a unique random key
2. Hashed using SHA-256
3. Signed using the user's RSA private key
4. Stored securely in the database

Upon retrieval, the system will:
1. Decrypt the document using the AES key
2. Verify the signature using the owner's public key
3. Check for tampering by comparing hashes

This ensures document confidentiality, integrity, and authenticity.
"""

SAMPLE_PDF_LIKE = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Sample PDF Document) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000184 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
277
%%EOF
"""
