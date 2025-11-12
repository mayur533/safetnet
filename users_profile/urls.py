"""
URL configuration for users app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'users'

urlpatterns = [
    # User registration and authentication
    path('', views.UserRegistrationView.as_view(), name='user-registration'),
    path('login/', views.UserLoginView.as_view(), name='user-login'),
    
    # User profile management
    path('profile/', views.UserProfileView.as_view(), name='user-profile-current'),
    path('<int:user_id>/', views.UserProfileView.as_view(), name='user-profile'),
    path('<int:user_id>/location/', views.UserLocationUpdateView.as_view(), name='user-location-update'),
    path('<int:user_id>/stats/', views.user_stats, name='user-stats'),
    
    # Family contacts management
    path('<int:user_id>/family_contacts/', views.FamilyContactListView.as_view(), name='family-contacts-list'),
    path('<int:user_id>/family_contacts/<int:contact_id>/', views.FamilyContactDetailView.as_view(), name='family-contact-detail'),
    
    # Community management
    path('<int:user_id>/communities/', views.CommunityMembershipListView.as_view(), name='community-memberships-list'),
    path('<int:user_id>/communities/join/', views.CommunityJoinView.as_view(), name='community-join'),
    path('<int:user_id>/communities/<str:community_id>/leave/', views.CommunityLeaveView.as_view(), name='community-leave'),
    
    # SOS functionality
    path('<int:user_id>/sos/', views.SOSTriggerView.as_view(), name='sos-trigger'),
    path('<int:user_id>/sos_events/', views.SOSEventListView.as_view(), name='sos-events-list'),
]
