# SafeTNet Sub-Admin Panel

A React TypeScript application for Sub-Administrators to manage geofences, security officers, incidents, and notifications within their organization.

## Features

- **Dashboard**: Overview of KPIs and recent activity
- **Geofences**: Create and manage geofences with interactive map drawing
- **Officers**: Manage security officers and their assignments
- **Incidents**: Track and manage security incidents
- **Notifications**: Send alerts to officers (Normal and Emergency types)

## Technology Stack

- React 18 with TypeScript
- React Router for navigation
- Tailwind CSS for styling
- Leaflet for map integration
- Axios for API communication
- React Hook Form for form handling
- Lucide React for icons

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- SafeTNet Backend API running on http://localhost:8000

### Installation

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables:
Create a `.env.local` file in the root directory:
```
REACT_APP_API_URL=http://localhost:8000/api
```

3. Start the development server:
```bash
npm start
```

The application will be available at http://localhost:3000

### Building for Production

```bash
npm run build
```

## API Endpoints

The application uses the following API endpoints:

- `POST /api/login/` - User authentication
- `GET /api/profile/` - Get user profile
- `GET /api/admin/geofences/` - List geofences
- `POST /api/admin/geofences/` - Create geofence
- `GET /api/admin/officers/` - List officers
- `POST /api/admin/officers/` - Create officer
- `GET /api/admin/incidents/` - List incidents
- `POST /api/admin/incidents/` - Create incident
- `POST /api/subadmin/notifications/send/` - Send notification
- `GET /api/subadmin/dashboard-kpis/` - Get dashboard KPIs

## Authentication

The application uses JWT authentication. Only users with the `SUB_ADMIN` role can access this panel. The access token is automatically refreshed when needed.

## Data Isolation

All data is filtered by the Sub-Admin's organization to ensure proper data isolation between different organizations.

## Map Integration

The geofences page includes an interactive map powered by Leaflet where users can:
- Draw polygons by clicking on the map
- View existing geofences
- Edit geofence boundaries

## Notification Types

- **Normal**: Regular push notification
- **Emergency**: Urgent alert with siren tone that overrides silent mode

## Target Types

- **All Officers**: Send to all active officers in the organization
- **Geofence Officers**: Send to officers assigned to a specific geofence
- **Specific Officers**: Send to selected officers
- **Sub Admin Only**: Send to the sub-admin only

## Development

### Project Structure

```
src/
├── components/          # Reusable components
│   ├── Layout.tsx      # Main layout with sidebar
│   └── ProtectedRoute.tsx # Route protection
├── contexts/           # React contexts
│   └── AuthContext.tsx # Authentication context
├── pages/              # Page components
│   ├── Dashboard.tsx
│   ├── Geofences.tsx
│   ├── Officers.tsx
│   ├── Incidents.tsx
│   └── Notifications.tsx
├── services/           # API services
│   └── api.ts         # API client and services
├── types/              # TypeScript type definitions
│   └── index.ts
└── App.tsx            # Main app component
```

### Key Features

1. **Responsive Design**: Works on desktop and mobile devices
2. **Real-time Updates**: Automatic token refresh and error handling
3. **Form Validation**: Client-side validation with error messages
4. **Loading States**: Proper loading indicators throughout the app
5. **Error Handling**: Comprehensive error handling with user-friendly messages

## Deployment

The application can be deployed to any static hosting service like:
- Vercel
- Netlify
- AWS S3 + CloudFront
- GitHub Pages

Make sure to update the `REACT_APP_API_URL` environment variable for production deployment.