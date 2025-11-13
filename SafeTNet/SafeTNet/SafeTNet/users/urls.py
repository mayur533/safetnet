from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

# Create router for ViewSets
router = DefaultRouter()
router.register(r'organizations', views.OrganizationViewSet, basename='organization')
router.register(r'geofences', views.GeofenceViewSet, basename='geofence')
router.register(r'users', views.UserListViewSet, basename='user')
router.register(r'alerts', views.AlertViewSet, basename='alert')
router.register(r'reports', views.GlobalReportViewSet, basename='report')

# Sub-Admin Panel routers
router.register(r'officers', views.SecurityOfficerViewSet, basename='officer')
router.register(r'incidents', views.IncidentViewSet, basename='incident')
router.register(r'notifications', views.NotificationViewSet, basename='notification')

# Promo Code router
router.register(r'promocode', views.PromoCodeViewSet, basename='promocode')

# Discount Emails router
router.register(r'discount-emails', views.DiscountEmailViewSet, basename='discount-email')

# User Replies router (read-only)
router.register(r'user-replies', views.UserReplyViewSet, basename='user-reply')

# User Details router (read-only)
router.register(r'user-details', views.UserDetailsViewSet, basename='user-detail')

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.CustomTokenObtainPairView.as_view(), name='login'),
    path('logout/', views.logout, name='logout'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', views.user_profile, name='user_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('request-password-reset/', views.request_password_reset, name='request_password_reset'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('test-auth/', views.test_auth, name='test_auth'),
    path('dashboard-kpis/', views.dashboard_kpis, name='dashboard_kpis'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    path('reports/<int:report_id>/download/', views.download_report, name='download_report'),
    path('admin/', include(router.urls)),
    
    # Sub-Admin Panel specific endpoints
    path('subadmin/notifications/send/', views.send_notification, name='send_notification'),
    path('subadmin/dashboard-kpis/', views.subadmin_dashboard_kpis, name='subadmin_dashboard_kpis'),
    
    # Notification read status
    path('notifications/<int:notification_id>/mark-read/', views.mark_notification_read, name='mark_notification_read'),
    
    # Analytics
    path('analytics/data/', views.analytics_data, name='analytics_data'),
]
