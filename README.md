Project Overview

MediVault is a security-focused backend infrastructure designed for the encrypted storage and management of sensitive medical records. 
As a Cybersecurity specialist, I architected this system with a "Defense-in-Depth" approach to ensure data confidentiality, integrity, and availability.

Key Features
  AES-256 File Encryption: All uploaded records (PDF/JPG/PNG) are encrypted at rest using the Cryptography.Fernet library.
  Brute-Force Protection: Automatic account lockout after 3 failed login attempts.
  Anti-Spoofing Validation: Implements "Magic Number" file signature verification to prevent malicious file uploads disguised with fake extensions.
  Audit Logging: Comprehensive internal logging of all security-sensitive events (logins, unauthorized access attempts, file deletions).
  Zero-Knowledge PIN Vault: Uses SHA-256 hashing for an additional "Access PIN" layer required for file viewing and uploading.


Technical Stack
  Language: Python 3.x
  Framework: Flask
  Database: MySQL (SQLAlchemy ORM)
  Encryption: Cryptography (Fernet)
  Auth: Flask-Login & Werkzeug (Scrypt hashing)
  Server: Waitress (Production WSGI)

Developer
  Abhay Pratap Singh
