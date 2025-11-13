# Safe T Net - Security Management System

A comprehensive security management platform with Admin and Sub-Admin portals for managing security operations, geofences, officers, incidents, and alerts.

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ installed
- Python 3.8+ installed
- PostgreSQL database

### Installation

The setup is **fully cross-platform** and works on Windows, Mac, and Linux automatically!

1. **Clone the repository**
   ```bash
   git clone git@github.com:mayur533/safetnet.git
   cd safetnet
   ```

2. **Install dependencies and setup**
   ```bash
   npm install
   ```
   This will automatically detect your OS and:
   - Install frontend dependencies
   - Create Python virtual environment (works on Windows/Mac/Linux)
   - Install backend Python requirements

3. **Configure environment**
   
   Create a `.env` file in `SafeTNet/` directory:
   ```env
   SECRET_KEY=your-secret-key
   DEBUG=True
   DATABASE_URL=postgresql://user:password@localhost:5432/safetnet
   ALLOWED_HOSTS=localhost,127.0.0.1
   ```

4. **Run database migrations**
   ```bash
   cd SafeTNet
   source venv/bin/activate
   python manage.py migrate
   python manage.py createsuperuser
   cd ..
   ```

5. **Start the application**
   ```bash
   npm start
   ```
   
   This starts:
   - Backend API at `http://localhost:8000`
   - Frontend Admin Panel at `http://localhost:3000`

## 📁 Project Structure

```
safetnet/
├── SafeTNet/              # Django Backend
│   ├── users/            # User management, Alerts, Incidents, Officers
│   ├── security/         # Security app
│   └── manage.py
├── safe-fleet-admin/     # Next.js Frontend
│   ├── src/
│   │   ├── app/         # Pages and routes
│   │   ├── components/  # React components
│   │   └── lib/         # Services and utilities
│   └── package.json
├── package.json          # Root package.json for easy startup
└── README.md
```

## 🎯 Features

### Main Admin Panel
- **Dashboard**: Real-time KPIs and statistics
- **Organizations**: Full CRUD operations
- **Users Management**: View, edit, delete users
- **Sub-Admins Management**: Create and manage sub-admins
- **Geofences**: View all geofences
- **Alerts**: Full alert management and resolution
- **Incidents**: View and resolve incidents
- **Promocodes**: Create and manage promotional codes
- **Notifications**: View sent notifications
- **Analytics**: Reports and analytics dashboard
- **Settings**: Profile and system settings

### Sub-Admin Panel
- **Dashboard**: Organization-specific KPIs
- **Geofences**: Create, edit, delete geofences with interactive map
- **Security Officers**: Full officer management
- **Notifications**: Send normal/emergency notifications
- **Incidents**: Track and resolve incidents within their geofence

## 🛠️ Tech Stack

### Backend
- Django 5.1.7
- Django REST Framework
- PostgreSQL
- JWT Authentication
- Django CORS Headers

### Frontend
- Next.js 15
- React 18
- TypeScript
- Tailwind CSS
- Radix UI
- Recharts
- Material Icons

## 📚 API Documentation

The backend API documentation is available at:
- Swagger: `http://localhost:8000/api/docs/`
- ReDoc: `http://localhost:8000/api/redoc/`

## 🔐 Authentication

- **JWT Token** based authentication
- Access token: 24 hours
- Refresh token: 30 days
- Role-based access control (SUPER_ADMIN, SUB_ADMIN)

## 📋 Environment Variables

### Backend (.env in SafeTNet/)
```env
SECRET_KEY=your-secret-key-here
DEBUG=True
DATABASE_URL=postgresql://user:password@localhost:5432/safetnet
ALLOWED_HOSTS=localhost,127.0.0.1
```

### Frontend (.env.local in safe-fleet-admin/)
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## 🗄️ Database Setup

1. Create PostgreSQL database:
   ```bash
   createdb safetnet
   ```

2. Run migrations:
   ```bash
   cd SafeTNet
   source venv/bin/activate
   python manage.py migrate
   ```

3. Create superuser:
   ```bash
   python manage.py createsuperuser
   ```

4. Load sample data (optional):
   ```bash
   python manage.py load_seed_data
   ```

## 🚦 Available Scripts

```bash
# Install dependencies (frontend + backend)
npm install

# Start both frontend and backend
npm start

# Start only backend
cd SafeTNet && source venv/bin/activate && python manage.py runserver

# Start only frontend
cd safe-fleet-admin && npm run dev

# Clean install
npm run clean
```

## 👥 Default Users

After running migrations, create users via Django admin or API:

1. **Super Admin**: Access to all features
2. **Sub-Admin**: Organization-specific features
3. **Users**: Regular app users

## 📝 License

MIT License

## 👤 Author

**mayur533**
- Email: mayurkhalate63@gmail.com
- GitHub: [@mayur533](https://github.com/mayur533)

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📞 Support

For issues or questions, please open an issue on GitHub.

---

**Safe T Net** - Secure. Protected. Managed.

