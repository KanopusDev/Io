# Io URL Shortener - Enterprise Architecture

## Overview
Io is an open-source URL shortener SaaS platform developed by Kanopus Development that provides customized API endpoints for users with tiered access based on verification status.

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLOUDFLARE CDN/WAF                      │
│                    (SSL/TLS Termination)                       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      LOAD BALANCER                             │
│                    (nginx/HAProxy)                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │   Frontend      │ │   Backend API   │ │   Admin API     │
    │ io.kanopus.org  │ │  knps.dev/api   │ │ knps.dev/admin  │
    │ (GitHub Pages)  │ │   (Flask App)   │ │   (Flask App)   │
    └─────────────────┘ └─────────────────┘ └─────────────────┘
                                │               │
                                └───────┬───────┘
                                        ▼
                            ┌─────────────────┐
                            │   SQLite DB     │
                            │   (with WAL)    │
                            └─────────────────┘
```

### Domain Structure

- **Frontend**: `io.kanopus.org` (GitHub Pages)
- **Backend API**: `knps.dev/api/v1/`
- **Admin API**: `knps.dev/admin/v1/`
- **User Custom Endpoints**: `io.kanopus.org/{username}`
- **Short URL Resolution**: `io.kanopus.org/s/{short_code}`

## Component Architecture

### 1. Backend Services (Flask)

#### Core Services Architecture
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
│  │   (Redis-like)  │ │                 │ │                 │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    Data Access Layer                           │
├─────────────────────────────────────────────────────────────────┤
│                      SQLite Database                           │
└─────────────────────────────────────────────────────────────────┘
```

### 2. Database Schema Design

#### Core Tables
```sql
-- Users Table
users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    api_key VARCHAR(255) UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    monthly_requests INTEGER DEFAULT 0,
    last_request_reset DATETIME DEFAULT CURRENT_TIMESTAMP
)

-- URLs Table
urls (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    original_url TEXT NOT NULL,
    short_code VARCHAR(10) UNIQUE NOT NULL,
    custom_alias VARCHAR(50),
    title VARCHAR(255),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)

-- Analytics Table
analytics (
    id INTEGER PRIMARY KEY,
    url_id INTEGER NOT NULL,
    user_agent TEXT,
    ip_address VARCHAR(45),
    referer TEXT,
    country VARCHAR(50),
    city VARCHAR(100),
    device_type VARCHAR(50),
    browser VARCHAR(50),
    clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url_id) REFERENCES urls(id)
)

-- Rate Limiting Table
rate_limits (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    requests_count INTEGER DEFAULT 0,
    window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)

-- Admin Actions Table
admin_actions (
    id INTEGER PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    target_user_id INTEGER,
    target_url_id INTEGER,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id)
)
```

### 3. API Architecture

#### Public API Endpoints
```
POST   /api/v1/auth/register          # User registration
POST   /api/v1/auth/login             # User authentication
POST   /api/v1/auth/refresh           # Token refresh
POST   /api/v1/auth/logout            # User logout

GET    /api/v1/user/profile           # Get user profile
PUT    /api/v1/user/profile           # Update user profile
DELETE /api/v1/user/account           # Delete user account

POST   /api/v1/urls                   # Create short URL
GET    /api/v1/urls                   # List user URLs
GET    /api/v1/urls/{id}              # Get specific URL
PUT    /api/v1/urls/{id}              # Update URL
DELETE /api/v1/urls/{id}              # Delete URL

GET    /api/v1/analytics/{url_id}     # Get URL analytics
GET    /api/v1/analytics/summary      # Get user analytics summary
```

#### Custom User API Endpoints
```
POST   /api/v1/{username}/shorten     # Create short URL via custom endpoint
GET    /api/v1/{username}/urls        # List URLs via custom endpoint
GET    /api/v1/{username}/analytics   # Get analytics via custom endpoint
```

#### Admin API Endpoints
```
GET    /admin/v1/users                # List all users
GET    /admin/v1/users/{id}           # Get specific user
PUT    /admin/v1/users/{id}/verify    # Verify user
PUT    /admin/v1/users/{id}/suspend   # Suspend user
DELETE /admin/v1/users/{id}           # Delete user

GET    /admin/v1/urls                 # List all URLs
DELETE /admin/v1/urls/{id}            # Delete any URL
GET    /admin/v1/analytics/global     # Global analytics
GET    /admin/v1/audit-logs           # Admin action logs
```

### 4. Security Architecture

#### Authentication & Authorization
```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Layer                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   JWT Tokens    │ │   API Keys      │ │   RBAC System   │   │
│  │   (Access/      │ │   (Custom API   │ │   (Admin/User/  │   │
│  │   Refresh)      │ │   Endpoints)    │ │   Verified)     │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │  Rate Limiting  │ │   Input         │ │   CORS &        │   │
│  │  (Per User/     │ │   Validation    │ │   Security      │   │
│  │  Per Endpoint)  │ │   & Sanitization│ │   Headers       │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

#### Security Measures
- **Password Security**: bcrypt hashing with salt rounds
- **JWT Implementation**: Access tokens (15min) + Refresh tokens (7 days)
- **API Key Security**: UUID4-based API keys for custom endpoints
- **Rate Limiting**: Redis-based distributed rate limiting
- **Input Validation**: Comprehensive validation using Marshmallow
- **CORS Configuration**: Strict origin policies
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.

### 5. Frontend Architecture

#### Client-Side Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    Frontend (GitHub Pages)                     │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Dashboard     │ │   URL Manager   │ │   Analytics     │   │
│  │   (Vanilla JS)  │ │   (Vanilla JS)  │ │   (Chart.js)    │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Auth Module   │ │   API Client    │ │   State Manager │   │
│  │   (Login/Reg)   │ │   (Fetch API)   │ │   (localStorage)│   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    Tailwind CSS Styling                        │
└─────────────────────────────────────────────────────────────────┘
```

#### Frontend Structure
```
/frontend
├── /assets
│   ├── /css
│   │   └── styles.css (Tailwind compiled)
│   ├── /js
│   │   ├── auth.js
│   │   ├── dashboard.js
│   │   ├── analytics.js
│   │   └── api-client.js
│   └── /images
├── /pages
│   ├── index.html (Landing page)
│   ├── dashboard.html
│   ├── analytics.html
│   └── docs.html (API documentation)
└── /components
    ├── navbar.js
    ├── modal.js
    └── charts.js
```

### 6. Performance & Scalability

#### Caching Strategy
```
┌─────────────────────────────────────────────────────────────────┐
│                       Caching Layers                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   CDN Cache     │ │   Application   │ │   Database      │   │
│  │   (Cloudflare)  │ │   Cache         │ │   Query Cache   │   │
│  │   Static Assets │ │   (Flask-Cache) │ │   (SQLite WAL)  │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

#### Database Optimization
- **SQLite WAL Mode**: Write-Ahead Logging for better concurrency
- **Database Indexes**: Strategic indexing on frequently queried columns
- **Connection Pooling**: Efficient database connection management
- **Query Optimization**: Prepared statements and query analysis

### 7. Monitoring & Logging

#### Observability Stack
```
┌─────────────────────────────────────────────────────────────────┐
│                    Monitoring & Logging                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Application   │ │   Error         │ │   Performance   │   │
│  │   Logs          │ │   Tracking      │ │   Metrics       │   │
│  │   (Structured)  │ │   (Sentry)      │ │   (Custom)      │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Health        │ │   Analytics     │ │   Audit Logs    │   │
│  │   Checks        │ │   Dashboard     │ │   (Admin        │   │
│  │   (/health)     │ │                 │ │   Actions)      │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### 8. Deployment Architecture

#### Infrastructure Layout
```
┌─────────────────────────────────────────────────────────────────┐
│                      Kanopus Server                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Reverse       │ │   Flask Apps    │ │   SQLite DB     │   │
│  │   Proxy         │ │   (Gunicorn)    │ │   + Backups     │   │
│  │   (nginx)       │ │   Multiple      │ │                 │   │
│  │                 │ │   Workers       │ │                 │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Log           │ │   Monitoring    │ │   Backup        │   │
│  │   Management    │ │   Services      │ │   Services      │   │
│  │   (logrotate)   │ │                 │ │   (Cron Jobs)   │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Business Logic Implementation

### 1. User Verification System
- **Unverified Users**: 1000 API requests/month limit
- **Verified Users**: Unlimited API requests
- **Custom Endpoints**: Only available for verified users
- **Admin Verification**: Manual verification process through admin panel

### 2. Rate Limiting Strategy
- **Per-User Limits**: Based on verification status
- **Per-Endpoint Limits**: Different limits for different endpoints
- **IP-based Limits**: Additional protection against abuse
- **Sliding Window**: Accurate rate limiting implementation

### 3. Analytics Engine
- **Real-time Tracking**: Click tracking with geographic data
- **Privacy Compliance**: IP anonymization options
- **Comprehensive Metrics**: User agents, referrers, device types
- **Export Capabilities**: Data export for verified users

### 4. URL Management
- **Custom Aliases**: User-defined short codes
- **Expiration Dates**: Time-based URL expiration
- **Bulk Operations**: Mass URL management capabilities
- **QR Code Generation**: Automatic QR code creation

## Security Considerations

### 1. Data Protection
- **Encryption at Rest**: Database encryption
- **Encryption in Transit**: HTTPS everywhere
- **Personal Data**: Minimal data collection
- **Data Retention**: Configurable retention policies

### 2. Abuse Prevention
- **URL Validation**: Malicious URL detection
- **Content Filtering**: Prohibited content blocking
- **Spam Protection**: Anti-spam measures
- **Bot Detection**: Automated traffic identification

### 3. Compliance
- **GDPR Compliance**: Data protection regulations
- **Privacy Policy**: Clear privacy guidelines
- **Terms of Service**: Comprehensive ToS
- **Audit Trails**: Complete action logging

## Disaster Recovery & Backup

### 1. Backup Strategy
- **Database Backups**: Automated daily backups
- **Code Backups**: Git-based version control
- **Configuration Backups**: System configuration snapshots
- **Cross-region Storage**: Backup replication

### 2. Recovery Procedures
- **RTO Target**: 4 hours maximum downtime
- **RPO Target**: 1 hour maximum data loss
- **Failover Procedures**: Documented recovery steps
- **Testing Schedule**: Monthly disaster recovery tests

## Cost Optimization

### 1. Resource Efficiency
- **SQLite Benefits**: No database server costs
- **Static Hosting**: GitHub Pages for frontend
- **CDN Integration**: Cloudflare free tier
- **Efficient Caching**: Reduced server load

### 2. Scaling Considerations
- **Horizontal Scaling**: Multiple Flask instances
- **Database Sharding**: Future SQLite partitioning
- **CDN Optimization**: Global content distribution
- **Load Balancing**: Traffic distribution

## Future Enhancements

### 1. Advanced Features
- **Team Collaboration**: Multi-user organizations
- **Advanced Analytics**: Machine learning insights
- **API Webhooks**: Real-time notifications
- **White-label Solutions**: Custom branding options

### 2. Technical Improvements
- **Microservices Migration**: Service decomposition
- **Database Upgrade**: PostgreSQL migration path
- **Container Deployment**: Docker containerization
- **CI/CD Pipeline**: Automated deployment

This architecture provides a solid foundation for an enterprise-grade URL shortener while maintaining the simplicity requested for the tech stack. The design emphasizes security, scalability, and maintainability while keeping operational costs low.
