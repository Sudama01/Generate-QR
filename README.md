# QR Pro App

## Overview
A full-featured QR code generator and scanner web application built with Flask. Users can generate QR codes from text or URLs, scan QR codes using their device camera, and track their history.

## Current State
- MVP fully functional with all core features implemented
- PostgreSQL database connected and tables created
- User authentication system working with password hashing
- QR generation and scanning operational
- CSRF protection enabled for all forms
- Secure session management

## Features
- **QR Code Generation**: Create QR codes from any text or URL
- **QR Code Scanning**: Use device camera to scan QR codes via html5-qrcode library
- **User Authentication**: Register/login system with session management and password hashing
- **History Tracking**: All generated and scanned QR codes are saved (for logged-in users)
- **Theme Switching**: Dark/light mode with per-user persistence
- **Analytics Dashboard**: View usage statistics and recent activity
- **REST API**: JWT-authenticated endpoints for mobile/external integration
- **Download**: Export generated QR codes as PNG images
- **Security**: CSRF protection, password hashing (Werkzeug), secure sessions

## Project Architecture

### Tech Stack
- **Backend**: Flask (Python)
- **Database**: PostgreSQL (via SQLAlchemy ORM)
- **Frontend**: Bootstrap 5, html5-qrcode library
- **Authentication**: Session-based + JWT for API
- **Security**: Flask-WTF (CSRF), Werkzeug (password hashing)

### File Structure
```
app.py              # Main Flask application
.gitignore          # Git ignore rules
replit.md           # This documentation
```

### Database Models
- **User** (table: `users`): id, username, password_hash, theme, created_at
- **History** (table: `history`): id, user_id, action (generated/scanned), content, timestamp

### API Endpoints
- `POST /api/token` - Get JWT token (username/password in JSON body)
- `POST /api/generate` - Generate QR code (JWT required, content in JSON body)
- `POST /api/save_scan` - Save scanned QR content

### Web Routes
- `/` - Home page with QR generation and scanning
- `/login` - User login
- `/register` - User registration
- `/logout` - Logout
- `/dashboard` - Analytics and activity history
- `/generate` - Form POST to generate QR
- `/download` - Download QR as PNG

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string (auto-configured)
- `SESSION_SECRET` - Flask session secret key (required for production)

## Security Notes
- Passwords are hashed using Werkzeug's secure password hashing
- CSRF protection is enabled for all form submissions
- API endpoints use JWT authentication
- For production deployment, ensure `SESSION_SECRET` is set to a stable value to prevent token invalidation across restarts

## Running the App
The app runs on port 5000 and is configured via the workflow "QR Pro App".

## Deployment
For production deployment:
1. Ensure `SESSION_SECRET` environment variable is set
2. The app uses gunicorn-compatible setup
3. Database tables are auto-created on startup

## Future Enhancements
- OAuth integration (Google login)
- QR code customization (colors, logos)
- Batch QR generation
- Export history to CSV/PDF
- QR templates (vCard, WiFi, etc.)
