# Orchida - Secure Cloud Storage Platform

## Overview
Orchida is a sophisticated Flask-based cloud storage platform that prioritizes security and user experience. The application implements advanced security measures, real-time file scanning, and end-to-end encryption for all user data.

## Quick Start with Docker

### Prerequisites
- Docker
- Docker Compose

### Running with Docker
1. Clone the repository:
```bash
git clone [repository-url]
cd Projet_Flask
```

2. Build and start the containers:
```bash
docker-compose up --build
```

The application will be available at `http://localhost:5000`

> Note: The application comes with default environment variables for development. If you want to use your own VirusTotal API key or customize other settings, create a `.env` file in the project root with your desired values.

### Default Login Credentials

#### Admin Account
- Email: admin@example.com
- Password: admin1234

#### User Account
- Email: user@example.com
- Password: user1234

### Docker Configuration
The application uses the following Docker services:
- Web application (Flask)
- SQLite database (persistent volume)
- File storage (persistent volume)

### Docker Environment Variables
Create a `.env` file in the project root:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

### Docker Volumes
- `./data/db` - SQLite database
- `./uploads` - User uploaded files
- `./keys` - RSA keys for encryption

### Docker Commands
```bash
# Start the application
docker-compose up

# Start in detached mode
docker-compose up -d

# Stop the application
docker-compose down

# View logs
docker-compose logs -f

# Rebuild containers
docker-compose up --build

# Remove all containers and volumes
docker-compose down -v
```

## Installation (Without Docker)

### Prerequisites
- Python 3.8 or higher
- libmagic for file type detection
- SQLite database
- Virtual environment (recommended)

### Setup Instructions

1. Clone the repository:
```bash
git clone [repository-url]
cd Projet_Flask
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install python-magic  # For file type detection
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Create necessary directories:
```bash
mkdir uploads
mkdir keys
```

6. Set up environment variables:
Create a `.env` file in the project root with the following variables:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

7. Run the application:
```bash
flask run
```

The application will be available at `http://localhost:5000`

## Core Features

### 1. User Management System
- **User Roles**
  - Regular users with 5GB default storage limit
  - Admin users with full system access
  - Group-based access control

- **Authentication System**
  - Email-based registration
  - Secure password hashing
  - Google reCAPTCHA integration
  - Custom mathematical CAPTCHA
  - Rate limiting with exponential backoff (5s, 10s, 20s, etc., max 300s)
  - Session-based authentication
  - Remember me functionality (30-day sessions)
  - Password reset functionality

### 2. File Management System

#### File Upload Security
- **VirusTotal Integration**
  - Real-time file scanning using VirusTotal API v3
  - SHA-256 hash verification
  - Malicious and suspicious file detection
  - Automatic blocking of flagged files

- **File Validation**
  - MIME type verification using python-magic
  - File size limits (10MB per file)
  - Allowed extensions check
  - Secure filename handling
  - Path traversal prevention

#### Storage Features
- **File Organization**
  - Hierarchical folder structure
  - Group-based folder sharing
  - File starring capability
  - File status tracking (complete, paused)
  - File preview functionality

- **File Operations**
  - Upload with progress tracking
  - Download with secure delivery
  - Pause/Resume uploads
  - Cancel uploads
  - Secure file deletion
  - Folder download as ZIP

### 3. Messaging System

#### Secure Communication
- **End-to-End Encryption**
  - AES-256 for message content
  - RSA-2048 for key exchange
  - HMAC-SHA256 for integrity
  - Digital signatures
  - Message deletion capability

- **Message Features**
  - Real-time delivery
  - Read receipts
  - Message history
  - Per-user message deletion
  - Original content preservation for sender

### 4. Group Management

#### Group Features
- **Group Operations**
  - Group creation and deletion
  - User assignment to groups
  - Group-based file sharing
  - Group-specific announcements
  - Group folder management

### 5. Announcement System

#### Announcement Features
- **Communication**
  - System-wide announcements
  - Group-specific announcements
  - Author tracking
  - Timestamp recording
  - Announcement deletion

### 6. Security Features

#### Access Control
- **Permission Management**
  - Role-based access control
  - Group-based permissions
  - Folder-level access control
  - File-level access control
  - Admin override capabilities

#### Data Protection
- **Storage Security**
  - Secure file storage
  - Access logging
  - Secure file deletion
  - Storage limit enforcement
  - MIME type verification

### 7. Administrative Features

#### Admin Controls
- **User Management**
  - User creation and deletion
  - Password reset capability
  - Storage limit modification
  - User group management
  - User activity monitoring

- **System Management**
  - Group administration
  - Announcement management
  - System-wide settings
  - User storage monitoring
  - Access control management

### 8. API Endpoints

#### User Management
- User registration and authentication
- Profile management
- Password reset
- Session management

#### File Operations
- File upload with VirusTotal scan
- File download
- File deletion
- Folder management
- File preview

#### Messaging
- Message sending
- Message retrieval
- Message deletion
- Read status management

#### Group Management
- Group creation/deletion
- User assignment
- Group folder management
- Group announcement handling

### 9. Installation Requirements

#### System Dependencies
- Python 3.8 or higher
- libmagic for file type detection
- SQLite database
- Virtual environment (recommended)

#### Python Dependencies
- Flask and extensions
- python-magic
- cryptography
- requests
- Other dependencies in requirements.txt

### 10. Security Best Practices

#### File Upload Security
- Pre-upload validation
- VirusTotal integration
- Secure storage
- Access control
- Regular security audits

#### Session Security
- Secure cookie configuration
- Session timeout
- CSRF protection
- Rate limiting
- Access logging

## License
[Specify your license here]

## Support
For support, please contact us.