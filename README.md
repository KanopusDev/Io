# Io URL Shortener

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![Flask](https://img.shields.io/badge/Flask-2.x-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

Io is an enterprise-grade URL shortener SaaS platform that provides customized URL shortening services with comprehensive analytics, user management, and API access. Named after Jupiter's moon Io, this application is designed to be scalable, secure, and feature-rich while maintaining simplicity in its technology stack.

## Features

### Core Functionality
- **URL Shortening**: Create short, memorable links for any valid URL
- **Custom Aliases**: Define your own custom short codes
- **Link Expiration**: Set expiration dates for temporary links
- **QR Code Generation**: Automatically generate QR codes for your short links
- **Preview Mode**: Preview destination URLs before visiting
- **Public API**: Create temporary short links without authentication

### User Management
- **User Verification**: Tiered access based on verification status
- **API Keys**: Secure API access for registered users
- **Custom Endpoints**: Personalized API endpoints for verified users
- **Rate Limiting**: Smart rate limiting based on user status and endpoint type

### Analytics & Insights
- **Click Tracking**: Monitor how many times your links are accessed
- **Geographic Data**: Track visitor locations and regional trends
- **Device Analytics**: Understand what devices your users are using
- **Referrer Tracking**: See where your traffic is coming from
- **Export Capabilities**: Export analytics data for further analysis

### Security
- **JWT Authentication**: Secure token-based authentication
- **RBAC System**: Role-based access control for administrators
- **Comprehensive Logging**: Full audit trail of administrative actions
- **Input Validation**: Thorough validation and sanitization of all inputs
- **Security Headers**: Strict security policies and headers

### Administration
- **Admin Dashboard**: Comprehensive dashboard for system oversight
- **User Management**: Verify, suspend, or delete user accounts
- **URL Management**: Monitor and manage all shortened URLs
- **Global Analytics**: System-wide analytics and usage trends

## Technology Stack

### Backend
- **Framework**: Flask (Python)
- **Database**: SQLite with Write-Ahead Logging (WAL)
- **Authentication**: JWT (Flask-JWT-Extended)
- **Rate Limiting**: Flask-Limiter
- **Input Validation**: Marshmallow
- **ORM**: SQLAlchemy
- **Logging**: Structlog for structured logging

### Frontend
- **Framework**: Vanilla JavaScript
- **Styling**: Tailwind CSS
- **Charts**: Chart.js for analytics visualization
- **State Management**: Browser localStorage

### Infrastructure
- **Web Server**: Gunicorn with multiple workers
- **Reverse Proxy**: Nginx
- **CDN**: Cloudflare for static assets and DDoS protection
- **Hosting**: On-premises deployment with high availability

## Architecture

Io follows a clean, service-oriented architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Flask Application                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Auth Service  │ │   URL Service   │ │  Analytics      │   │
│  │                 │ │                 │ │   Service       │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │  Rate Limiter   │ │   User Service  │ │   Admin Service │   │
│  │                 │ │                 │ │                 │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    Data Access Layer                           │
├─────────────────────────────────────────────────────────────────┤
│                      SQLite Database                           │
└─────────────────────────────────────────────────────────────────┘
```

For detailed architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Installation

### Prerequisites
- Python 3.10+
- pip (Python package manager)
- git (for cloning the repository)

### Clone the Repository
```bash
git clone https://github.com/kanopusdev/io.git
cd io
```

### Set Up a Virtual Environment
```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Configuration
1. Copy the sample environment file:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your configuration settings:
```
# Application Settings
FLASK_ENV=development
DEBUG=True
SECRET_KEY=your-secret-key-here
HOST=127.0.0.1
PORT=5000

# Database Settings
SQLALCHEMY_DATABASE_URI=sqlite:///instance/io.db

# JWT Settings
JWT_SECRET_KEY=your-jwt-secret-key-here
JWT_ACCESS_TOKEN_EXPIRES_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRES_DAYS=7

# Domain Settings
SHORT_DOMAIN=localhost:5000

# Admin User
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=secure-admin-password

# Rate Limits
UNVERIFIED_USER_MONTHLY_LIMIT=1000
VERIFIED_USER_MONTHLY_LIMIT=999999999
```

### Initialize the Database
```bash
cd backend
python app.py
```

## Running the Application

### Development Mode
```bash
cd backend
python app.py
```

The application will be available at `http://localhost:5000`.

## API Documentation

### Authentication
```
POST   /api/v1/auth/register          # User registration
POST   /api/v1/auth/login             # User authentication
POST   /api/v1/auth/refresh           # Token refresh
POST   /api/v1/auth/logout            # User logout
```

### User Management
```
GET    /api/v1/user/profile           # Get user profile
PUT    /api/v1/user/profile           # Update user profile
DELETE /api/v1/user/account           # Delete user account
```

### URL Shortening
```
POST   /api/v1/urls                   # Create short URL
GET    /api/v1/urls                   # List user URLs
GET    /api/v1/urls/{id}              # Get specific URL
PUT    /api/v1/urls/{id}              # Update URL
DELETE /api/v1/urls/{id}              # Delete URL
```

### Analytics
```
GET    /api/v1/analytics/{url_id}     # Get URL analytics
GET    /api/v1/analytics/summary      # Get user analytics summary
```

### Public Endpoints
```
GET    /health                        # Health check endpoint
GET    /status                        # Service status information
GET    /{short_code}                  # Redirect to original URL
GET    /api/info/{short_code}         # Get URL information
POST   /api/v1/public/shorten         # Create temporary URL (no auth)
GET    /api/v1/public/qr/{short_code} # Generate QR code
```

For complete API documentation, run the application and visit `/docs`.

## Testing

To run tests:

```bash
pytest
```

For running tests with coverage:

```bash
coverage run -m pytest
coverage report
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for our code of conduct and contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Developed by Kanopus Development
- Inspired by enterprise-grade URL shortener services
- Built with open-source technologies

## Contact

For questions, feedback, or support:
- Email: [support@kanopus.org](mailto:support@kanopus.org)
- Website: [https://io.kanopus.org](https://io.kanopus.org)
- GitHub: [https://github.com/kanopusdev/io](https://github.com/kanopusdev/io)
