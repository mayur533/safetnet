# SafeTNet Main Admin Panel - Production Ready

A comprehensive Django REST API and React frontend for managing geofencing alerts and reports with role-based access control, real-time monitoring, and production-ready deployment.

## 🚀 Features

### Backend Features
- **Role-Based Access Control (RBAC)**: SUPER_ADMIN, SUB_ADMIN, and USER roles with proper permissions
- **Multi-tenant Architecture**: Organization-based data isolation
- **Real-time Alerts**: Geofence enter/exit/violation monitoring
- **Report Generation**: Multiple report types with CSV export
- **Dashboard KPIs**: Real-time metrics and system health monitoring
- **Security**: CSRF protection, input sanitization, JWT authentication
- **API Documentation**: Swagger/OpenAPI with interactive documentation
- **Comprehensive Testing**: Unit, integration, and performance tests

### Frontend Features
- **Modern React UI**: Material-UI components with responsive design
- **Real-time Polling**: Automatic alert updates every 10 seconds
- **Advanced Filtering**: Filter alerts by type, severity, status
- **Interactive Reports**: Date picker, report generation, CSV download
- **Dashboard Analytics**: KPI cards with color-coded indicators
- **Organization Isolation**: Users only see their organization's data

## 📁 Project Structure

```
SafeTNet/
├── SafeTNet/                 # Django project settings
├── users/                    # Main Django app
│   ├── models.py            # Database models
│   ├── views.py             # API views and endpoints
│   ├── serializers.py       # Data serialization
│   ├── permissions.py       # RBAC permissions
│   ├── utils.py             # Input sanitization utilities
│   ├── tests.py             # Comprehensive test suite
│   └── management/          # Django management commands
├── admin-ui/                 # React frontend
│   ├── src/
│   │   ├── pages/           # React components
│   │   ├── services/        # API service layer
│   │   ├── types/           # TypeScript definitions
│   │   └── contexts/        # React contexts
├── Dockerfile               # Production Docker configuration
├── docker-compose.yml       # Multi-service Docker setup
├── nginx.conf               # Nginx configuration
├── requirements.txt         # Python dependencies
├── initial_data.json        # Sample seed data
├── pytest.ini              # Test configuration
└── DEPLOYMENT_GUIDE.md     # Comprehensive deployment guide
```

## 🛠️ Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for frontend development)
- Python 3.11+ (for backend development)

### 1. Clone and Setup
```bash
git clone <repository-url>
cd SafeTNet

# Copy environment variables
cp .env.example .env
# Edit .env with your configuration
```

### 2. Docker Deployment (Recommended)
```bash
# Start all services
docker-compose up -d --build

# Load sample data
docker-compose exec web python manage.py loaddata initial_data.json

# Access the application
# Backend API: http://localhost:8000/api/docs/
# Frontend: http://localhost:3000
```

### 3. Manual Setup
```bash
# Backend setup
pip install -r requirements.txt
python manage.py migrate
python manage.py loaddata initial_data.json
python manage.py runserver

# Frontend setup (in admin-ui directory)
cd admin-ui
npm install
npm start
```

## 🔐 Default Credentials

### Super Admin
- **Username**: `superadmin`
- **Password**: `testpass123!`
- **Access**: Full system access

### Sub-Admins
- **Username**: `subadmin1` / `subadmin2`
- **Password**: `testpass123!`
- **Access**: Organization-specific data only

### Regular Users
- **Username**: `user1` / `user2`
- **Password**: `testpass123!`
- **Access**: Limited to their organization

## 📊 API Endpoints

### Authentication
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/refresh/` - Token refresh
- `GET /api/auth/profile/` - User profile
- `POST /api/auth/logout/` - User logout

### Organizations (Super Admin only)
- `GET /api/auth/admin/organizations/` - List organizations
- `POST /api/auth/admin/organizations/` - Create organization
- `GET /api/auth/admin/organizations/{id}/` - Get organization
- `PUT /api/auth/admin/organizations/{id}/` - Update organization
- `DELETE /api/auth/admin/organizations/{id}/` - Delete organization

### Sub-Admins (Super Admin only)
- `GET /api/auth/admin/subadmins/` - List sub-admins
- `POST /api/auth/admin/subadmins/` - Create sub-admin
- `GET /api/auth/admin/subadmins/{id}/` - Get sub-admin
- `PUT /api/auth/admin/subadmins/{id}/` - Update sub-admin
- `DELETE /api/auth/admin/subadmins/{id}/` - Delete sub-admin

### Geofences
- `GET /api/auth/admin/geofences/` - List geofences
- `POST /api/auth/admin/geofences/` - Create geofence
- `GET /api/auth/admin/geofences/{id}/` - Get geofence
- `PUT /api/auth/admin/geofences/{id}/` - Update geofence
- `DELETE /api/auth/admin/geofences/{id}/` - Delete geofence

### Alerts
- `GET /api/auth/admin/alerts/` - List alerts (with filters)
- `POST /api/auth/admin/alerts/` - Create alert
- `GET /api/auth/admin/alerts/{id}/` - Get alert
- `PUT /api/auth/admin/alerts/{id}/` - Update alert
- `PATCH /api/auth/admin/alerts/{id}/` - Resolve alert
- `DELETE /api/auth/admin/alerts/{id}/` - Delete alert

### Reports (Super Admin only)
- `GET /api/auth/admin/reports/` - List reports
- `POST /api/auth/admin/reports/` - Create report
- `POST /api/auth/reports/generate/` - Generate report with metrics
- `GET /api/auth/reports/{id}/download/` - Download CSV report
- `DELETE /api/auth/admin/reports/{id}/` - Delete report

### Dashboard
- `GET /api/auth/dashboard-kpis/` - Get dashboard KPIs

### Documentation
- `GET /api/schema/` - OpenAPI schema
- `GET /api/docs/` - Swagger UI
- `GET /api/redoc/` - ReDoc documentation

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m performance

# Run with coverage
pytest --cov=users --cov-report=html
```

### Test Categories
- **Unit Tests**: Model validation, serializers, utilities
- **Integration Tests**: API endpoints, authentication flow
- **Performance Tests**: Bulk operations, response times
- **Security Tests**: Input sanitization, permission checks

## 🐳 Docker Services

### Production Services
- **web**: Django application with Gunicorn
- **db**: PostgreSQL database
- **redis**: Redis cache and message broker
- **nginx**: Reverse proxy and static file serving
- **celery**: Background task processing
- **celery-beat**: Scheduled task management

### Development Services
- **web-dev**: Django development server
- **db**: PostgreSQL database
- **redis**: Redis cache

## 📈 Monitoring & Logging

### Log Files
- **Application Logs**: `/var/log/safetnet/django.log`
- **Error Logs**: `/var/log/safetnet/error.log`
- **Nginx Logs**: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`
- **Database Logs**: `/var/log/postgresql/postgresql-*.log`

### Health Checks
- **Application**: `GET /api/schema/` (200 OK)
- **Database**: PostgreSQL connection check
- **Redis**: Redis ping check
- **Nginx**: HTTP response check

### Metrics
- **Dashboard KPIs**: Active geofences, alerts today, system health
- **Performance**: Response times, database queries, memory usage
- **Security**: Failed login attempts, permission violations

## 🔒 Security Features

### Authentication & Authorization
- **JWT Tokens**: Secure token-based authentication
- **Role-Based Access**: Granular permission system
- **Organization Isolation**: Multi-tenant data separation
- **Session Management**: Secure session handling

### Input Security
- **Input Sanitization**: XSS and SQL injection prevention
- **CSRF Protection**: Cross-site request forgery protection
- **Password Validation**: Strong password requirements
- **Email Validation**: Proper email format validation

### Infrastructure Security
- **HTTPS**: SSL/TLS encryption
- **Security Headers**: HSTS, X-Frame-Options, CSP
- **Rate Limiting**: API request rate limiting
- **Firewall**: UFW configuration
- **Fail2Ban**: Intrusion prevention

## 📚 Documentation

### API Documentation
- **Swagger UI**: Interactive API documentation at `/api/docs/`
- **ReDoc**: Alternative documentation at `/api/redoc/`
- **Postman Collection**: Complete API collection included
- **cURL Examples**: Command-line examples provided

### Deployment Documentation
- **DEPLOYMENT_GUIDE.md**: Comprehensive production deployment guide
- **Docker Configuration**: Production-ready containerization
- **Environment Setup**: Development and production configurations
- **Monitoring Setup**: Logging and monitoring configuration

## 🚀 Production Deployment

### Quick Production Deploy
```bash
# 1. Set environment variables
export DEBUG=False
export SECRET_KEY=your-secret-key
export DB_PASSWORD=your-db-password

# 2. Deploy with Docker
docker-compose -f docker-compose.prod.yml up -d

# 3. Load production data
docker-compose exec web python manage.py loaddata initial_data.json

# 4. Access application
# https://yourdomain.com/api/docs/
```

### Production Checklist
- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] Database backups configured
- [ ] Monitoring setup
- [ ] Security hardening applied
- [ ] Performance optimization
- [ ] Log rotation configured
- [ ] Health checks implemented

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

### Code Standards
- **Python**: PEP 8 compliance
- **JavaScript/TypeScript**: ESLint configuration
- **Tests**: Minimum 80% coverage
- **Documentation**: Comprehensive docstrings
- **Security**: Input validation and sanitization

## 📞 Support

### Troubleshooting
- Check the **DEPLOYMENT_GUIDE.md** for common issues
- Review application logs for error details
- Verify environment configuration
- Test API endpoints with provided examples

### Getting Help
- **Documentation**: Comprehensive guides included
- **API Examples**: Postman collection and cURL examples
- **Test Suite**: Extensive test coverage
- **Logs**: Detailed logging for debugging

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🎯 Roadmap

### Future Enhancements
- [ ] Real-time WebSocket notifications
- [ ] Advanced analytics dashboard
- [ ] Mobile application
- [ ] Third-party integrations
- [ ] Advanced reporting features
- [ ] Machine learning insights

---

**SafeTNet Main Admin Panel** - Production-ready geofencing management system with comprehensive monitoring, reporting, and security features.