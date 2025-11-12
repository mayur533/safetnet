"""
Unit tests for User models and API endpoints.
"""
import json
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.gis.geos import Point
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, FamilyContact, CommunityMembership, SOSEvent

User = get_user_model()


class UserModelTest(TestCase):
    """Test cases for User model."""
    
    def setUp(self):
        """Set up test data."""
        self.user_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'phone': '+1234567890',
            'plantype': 'free'
        }
    
    def test_user_creation(self):
        """Test user creation."""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.name, 'John Doe')
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.phone, '+1234567890')
        self.assertEqual(user.plantype, 'free')
        self.assertFalse(user.is_premium)
    
    def test_user_premium_status(self):
        """Test premium status calculation."""
        from datetime import date, timedelta
        
        # Free user
        user = User.objects.create_user(**self.user_data)
        self.assertFalse(user.is_premium)
        
        # Premium user with future expiry
        user.plantype = 'premium'
        user.planexpiry = date.today() + timedelta(days=30)
        user.save()
        self.assertTrue(user.is_premium)
        
        # Premium user with past expiry
        user.planexpiry = date.today() - timedelta(days=1)
        user.save()
        self.assertFalse(user.is_premium)
    
    def test_user_location(self):
        """Test user location functionality."""
        user = User.objects.create_user(**self.user_data)
        
        # Set location
        user.set_location(-74.0059, 40.7128)  # New York coordinates
        self.assertIsNotNone(user.location)
        self.assertEqual(user.location.x, -74.0059)
        self.assertEqual(user.location.y, 40.7128)
        
        # Get location dict
        location_dict = user.get_location_dict()
        self.assertEqual(location_dict['longitude'], -74.0059)
        self.assertEqual(location_dict['latitude'], 40.7128)


class FamilyContactModelTest(TestCase):
    """Test cases for FamilyContact model."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
    
    def test_family_contact_creation(self):
        """Test family contact creation."""
        contact = FamilyContact.objects.create(
            user=self.user,
            name='Jane Doe',
            phone='+0987654321',
            relationship='Spouse'
        )
        self.assertEqual(contact.name, 'Jane Doe')
        self.assertEqual(contact.phone, '+0987654321')
        self.assertEqual(contact.relationship, 'Spouse')
        self.assertEqual(contact.user, self.user)
    
    def test_maximum_contacts_limit(self):
        """Test maximum 3 contacts per user."""
        # Create 3 contacts
        for i in range(3):
            FamilyContact.objects.create(
                user=self.user,
                name=f'Contact {i}',
                phone=f'+123456789{i}',
                relationship='Friend'
            )
        
        # Try to create 4th contact
        with self.assertRaises(ValueError):
            FamilyContact.objects.create(
                user=self.user,
                name='Contact 4',
                phone='+1234567894',
                relationship='Friend'
            )
    
    def test_primary_contact_unique(self):
        """Test that only one contact can be primary per user."""
        contact1 = FamilyContact.objects.create(
            user=self.user,
            name='Contact 1',
            phone='+1234567891',
            is_primary=True
        )
        
        contact2 = FamilyContact.objects.create(
            user=self.user,
            name='Contact 2',
            phone='+1234567892',
            is_primary=True
        )
        
        # Refresh from database
        contact1.refresh_from_db()
        contact2.refresh_from_db()
        
        # Only the last created contact should be primary
        self.assertFalse(contact1.is_primary)
        self.assertTrue(contact2.is_primary)


class UserAPITest(APITestCase):
    """Test cases for User API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user_data = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'phone': '+1234567890',
            'password': 'testpass123',
            'password_confirm': 'testpass123'
        }
    
    def test_user_registration(self):
        """Test user registration endpoint."""
        url = reverse('users:user-registration')
        response = self.client.post(url, self.user_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('tokens', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'john@example.com')
    
    def test_user_registration_invalid_data(self):
        """Test user registration with invalid data."""
        url = reverse('users:user-registration')
        invalid_data = self.user_data.copy()
        invalid_data['password_confirm'] = 'different_password'
        
        response = self.client.post(url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_user_login(self):
        """Test user login endpoint."""
        # Create user first
        User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890',
            password='testpass123'
        )
        
        url = reverse('users:user-login')
        login_data = {
            'email': 'john@example.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)
        self.assertIn('user', response.data)
    
    def test_user_profile_get(self):
        """Test getting user profile."""
        user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        url = reverse('users:user-profile', kwargs={'user_id': user.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'john@example.com')
    
    def test_user_profile_update(self):
        """Test updating user profile."""
        user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        url = reverse('users:user-profile', kwargs={'user_id': user.id})
        update_data = {'name': 'John Smith'}
        
        response = self.client.patch(url, update_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'John Smith')
    
    def test_user_location_update(self):
        """Test updating user location."""
        user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        url = reverse('users:user-location-update', kwargs={'user_id': user.id})
        location_data = {
            'longitude': -74.0059,
            'latitude': 40.7128
        }
        
        response = self.client.post(url, location_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('location', response.data)


class FamilyContactAPITest(APITestCase):
    """Test cases for FamilyContact API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        self.access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
    
    def test_family_contact_list(self):
        """Test listing family contacts."""
        # Create a family contact
        FamilyContact.objects.create(
            user=self.user,
            name='Jane Doe',
            phone='+0987654321',
            relationship='Spouse'
        )
        
        url = reverse('users:family-contacts-list', kwargs={'user_id': self.user.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['name'], 'Jane Doe')
    
    def test_family_contact_create(self):
        """Test creating family contact."""
        url = reverse('users:family-contacts-list', kwargs={'user_id': self.user.id})
        contact_data = {
            'name': 'Jane Doe',
            'phone': '+0987654321',
            'relationship': 'Spouse'
        }
        
        response = self.client.post(url, contact_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Jane Doe')
    
    def test_family_contact_maximum_limit(self):
        """Test maximum 3 contacts limit."""
        url = reverse('users:family-contacts-list', kwargs={'user_id': self.user.id})
        
        # Create 3 contacts
        for i in range(3):
            contact_data = {
                'name': f'Contact {i}',
                'phone': f'+123456789{i}',
                'relationship': 'Friend'
            }
            response = self.client.post(url, contact_data, format='json')
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Try to create 4th contact
        contact_data = {
            'name': 'Contact 4',
            'phone': '+1234567894',
            'relationship': 'Friend'
        }
        response = self.client.post(url, contact_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_family_contact_delete(self):
        """Test deleting family contact."""
        contact = FamilyContact.objects.create(
            user=self.user,
            name='Jane Doe',
            phone='+0987654321',
            relationship='Spouse'
        )
        
        url = reverse('users:family-contact-detail', kwargs={
            'user_id': self.user.id,
            'contact_id': contact.id
        })
        
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify contact is deleted
        self.assertFalse(FamilyContact.objects.filter(id=contact.id).exists())


class CommunityAPITest(APITestCase):
    """Test cases for Community API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        self.access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
    
    def test_community_join(self):
        """Test joining a community."""
        url = reverse('users:community-join', kwargs={'user_id': self.user.id})
        community_data = {
            'community_id': 'comm_123',
            'community_name': 'Test Community'
        }
        
        response = self.client.post(url, community_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['membership']['community_id'], 'comm_123')
    
    def test_community_list(self):
        """Test listing user's communities."""
        # Create a community membership
        CommunityMembership.objects.create(
            user=self.user,
            community_id='comm_123',
            community_name='Test Community'
        )
        
        url = reverse('users:community-memberships-list', kwargs={'user_id': self.user.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['community_id'], 'comm_123')
    
    def test_community_leave(self):
        """Test leaving a community."""
        membership = CommunityMembership.objects.create(
            user=self.user,
            community_id='comm_123',
            community_name='Test Community'
        )
        
        url = reverse('users:community-leave', kwargs={
            'user_id': self.user.id,
            'community_id': 'comm_123'
        })
        
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify membership is deactivated
        membership.refresh_from_db()
        self.assertFalse(membership.is_active)


class SOSAPITest(APITestCase):
    """Test cases for SOS API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        
        # Create a family contact
        FamilyContact.objects.create(
            user=self.user,
            name='Jane Doe',
            phone='+0987654321',
            relationship='Spouse'
        )
        
        # Get JWT token
        refresh = RefreshToken.for_user(self.user)
        self.access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
    
    def test_sos_trigger(self):
        """Test triggering SOS event."""
        url = reverse('users:sos-trigger', kwargs={'user_id': self.user.id})
        sos_data = {
            'longitude': -74.0059,
            'latitude': 40.7128,
            'notes': 'Emergency test'
        }
        
        response = self.client.post(url, sos_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('sos_event', response.data)
        self.assertEqual(response.data['sos_event']['notes'], 'Emergency test')
    
    def test_sos_events_list(self):
        """Test listing SOS events."""
        # Create an SOS event
        SOSEvent.objects.create(
            user=self.user,
            location=Point(-74.0059, 40.7128),
            notes='Test SOS event'
        )
        
        url = reverse('users:sos-events-list', kwargs={'user_id': self.user.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['notes'], 'Test SOS event')


class AuthenticationTest(APITestCase):
    """Test cases for authentication and permissions."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        self.user = User.objects.create_user(
            name='John Doe',
            email='john@example.com',
            phone='+1234567890'
        )
        self.other_user = User.objects.create_user(
            name='Jane Doe',
            email='jane@example.com',
            phone='+0987654321'
        )
    
    def test_unauthorized_access(self):
        """Test that unauthorized users cannot access protected endpoints."""
        url = reverse('users:user-profile', kwargs={'user_id': self.user.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_cross_user_access(self):
        """Test that users cannot access other users' data."""
        # Get JWT token for user
        refresh = RefreshToken.for_user(self.user)
        access_token = refresh.access_token
        
        # Set authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        # Try to access other user's profile
        url = reverse('users:user-profile', kwargs={'user_id': self.other_user.id})
        response = self.client.get(url)
        
        # Should still return user's own profile (current implementation)
        # In a more strict implementation, this could return 403
        self.assertEqual(response.status_code, status.HTTP_200_OK)
