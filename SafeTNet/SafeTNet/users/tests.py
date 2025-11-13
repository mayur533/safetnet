import pytest
import json
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from factory import Faker, SubFactory, LazyAttribute
from factory.django import DjangoModelFactory
from unittest.mock import patch, MagicMock
import tempfile
import os

from users.models import User, Organization, Geofence, Alert, GlobalReport
from users.serializers import UserSerializer, AlertSerializer, GlobalReportSerializer
from users.utils import sanitize_string, validate_email, validate_username, validate_password_strength

User = get_user_model()


# Factory Classes
class OrganizationFactory(DjangoModelFactory):
    class Meta:
        model = Organization
    
    name = Faker('company')
    description = Faker('text', max_nb_chars=200)


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User
    
    username = Faker('user_name')
    email = Faker('email')
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    role = 'USER'
    organization = SubFactory(OrganizationFactory)
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        password = kwargs.pop('password', 'testpass123!')
        user = super()._create(model_class, *args, **kwargs)
        user.set_password(password)
        user.save()
        return user


class SuperAdminFactory(UserFactory):
    role = 'SUPER_ADMIN'
    organization = None


class SubAdminFactory(UserFactory):
    role = 'SUB_ADMIN'


class GeofenceFactory(DjangoModelFactory):
    class Meta:
        model = Geofence
    
    name = Faker('word')
    description = Faker('text', max_nb_chars=200)
    latitude = Faker('latitude')
    longitude = Faker('longitude')
    radius = Faker('pyint', min_value=10, max_value=1000)
    active = True
    organization = SubFactory(OrganizationFactory)


class AlertFactory(DjangoModelFactory):
    class Meta:
        model = Alert
    
    title = Faker('sentence', nb_words=4)
    description = Faker('text', max_nb_chars=500)
    alert_type = Faker('random_element', elements=['GEOFENCE_ENTER', 'GEOFENCE_EXIT', 'GEOFENCE_VIOLATION'])
    severity = Faker('random_element', elements=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    geofence = SubFactory(GeofenceFactory)
    user = SubFactory(UserFactory)


class GlobalReportFactory(DjangoModelFactory):
    class Meta:
        model = GlobalReport
    
    title = Faker('sentence', nb_words=3)
    description = Faker('text', max_nb_chars=300)
    report_type = Faker('random_element', elements=['GEOFENCE_ANALYTICS', 'USER_ACTIVITY', 'ALERT_SUMMARY'])
    generated_by = SubFactory(SuperAdminFactory)


# Test Classes
class UserModelTest(TestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.user = UserFactory(organization=self.organization)
    
    def test_user_creation(self):
        self.assertEqual(self.user.username, self.user.username)
        self.assertEqual(self.user.organization, self.organization)
        self.assertTrue(self.user.check_password('testpass123!'))
    
    def test_user_str_representation(self):
        expected = f"{self.user.username} ({self.user.role})"
        self.assertEqual(str(self.user), expected)
    
    def test_super_admin_creation(self):
        super_admin = SuperAdminFactory()
        self.assertEqual(super_admin.role, 'SUPER_ADMIN')
        self.assertIsNone(super_admin.organization)


class OrganizationModelTest(TestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
    
    def test_organization_creation(self):
        self.assertIsNotNone(self.organization.name)
        self.assertIsNotNone(self.organization.description)
    
    def test_organization_str_representation(self):
        self.assertEqual(str(self.organization), self.organization.name)


class GeofenceModelTest(TestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.geofence = GeofenceFactory(organization=self.organization)
    
    def test_geofence_creation(self):
        self.assertIsNotNone(self.geofence.name)
        self.assertEqual(self.geofence.organization, self.organization)
        self.assertTrue(self.geofence.active)
    
    def test_geofence_str_representation(self):
        expected = f"{self.geofence.name} ({self.geofence.organization.name})"
        self.assertEqual(str(self.geofence), expected)


class AlertModelTest(TestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.geofence = GeofenceFactory(organization=self.organization)
        self.user = UserFactory(organization=self.organization)
        self.alert = AlertFactory(geofence=self.geofence, user=self.user)
    
    def test_alert_creation(self):
        self.assertIsNotNone(self.alert.title)
        self.assertEqual(self.alert.geofence, self.geofence)
        self.assertEqual(self.alert.user, self.user)
        self.assertFalse(self.alert.is_resolved)
    
    def test_alert_resolution(self):
        resolver = UserFactory(organization=self.organization)
        self.alert.resolve(resolver)
        
        self.assertTrue(self.alert.is_resolved)
        self.assertEqual(self.alert.resolved_by, resolver)
        self.assertIsNotNone(self.alert.resolved_at)
    
    def test_alert_str_representation(self):
        expected = f"{self.alert.title} ({self.alert.severity})"
        self.assertEqual(str(self.alert), expected)


class GlobalReportModelTest(TestCase):
    def setUp(self):
        self.super_admin = SuperAdminFactory()
        self.report = GlobalReportFactory(generated_by=self.super_admin)
    
    def test_report_creation(self):
        self.assertIsNotNone(self.report.title)
        self.assertEqual(self.report.generated_by, self.super_admin)
        self.assertFalse(self.report.is_generated)
    
    def test_report_generation(self):
        file_path = "/tmp/test_report.csv"
        self.report.mark_as_generated(file_path)
        
        self.assertTrue(self.report.is_generated)
        self.assertEqual(self.report.file_path, file_path)
        self.assertIsNotNone(self.report.generated_at)
    
    def test_report_str_representation(self):
        expected = f"{self.report.title} ({self.report.report_type})"
        self.assertEqual(str(self.report), expected)


class InputSanitizationTest(TestCase):
    def test_sanitize_string_basic(self):
        # Test basic sanitization
        result = sanitize_string("Hello World")
        self.assertEqual(result, "Hello World")
    
    def test_sanitize_string_xss_prevention(self):
        # Test XSS prevention
        malicious_input = "<script>alert('xss')</script>"
        with self.assertRaises(Exception):
            sanitize_string(malicious_input)
    
    def test_sanitize_string_sql_injection_prevention(self):
        # Test SQL injection prevention
        malicious_input = "'; DROP TABLE users; --"
        with self.assertRaises(Exception):
            sanitize_string(malicious_input)
    
    def test_sanitize_string_length_validation(self):
        # Test length validation
        long_string = "a" * 1001
        with self.assertRaises(Exception):
            sanitize_string(long_string, max_length=1000)
    
    def test_validate_email_valid(self):
        valid_email = "test@example.com"
        result = validate_email(valid_email)
        self.assertEqual(result, "test@example.com")
    
    def test_validate_email_invalid(self):
        invalid_email = "not-an-email"
        with self.assertRaises(Exception):
            validate_email(invalid_email)
    
    def test_validate_username_valid(self):
        valid_username = "testuser123"
        result = validate_username(valid_username)
        self.assertEqual(result, "testuser123")
    
    def test_validate_username_invalid(self):
        invalid_username = "ab"  # Too short
        with self.assertRaises(Exception):
            validate_username(invalid_username)
    
    def test_validate_password_strength_valid(self):
        valid_password = "StrongPass123!"
        # Should not raise exception
        validate_password_strength(valid_password)
    
    def test_validate_password_strength_invalid(self):
        invalid_password = "weak"
        with self.assertRaises(Exception):
            validate_password_strength(invalid_password)


class AuthenticationAPITest(APITestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.user = UserFactory(organization=self.organization)
        self.super_admin = SuperAdminFactory()
    
    def test_user_registration(self):
        url = reverse('register')
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'StrongPass123!',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'USER',
            'organization': self.organization.id
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='newuser').exists())
    
    def test_user_login(self):
        url = reverse('login')
        data = {
            'username': self.user.username,
            'password': 'testpass123!'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
    
    def test_user_login_invalid_credentials(self):
        url = reverse('login')
        data = {
            'username': self.user.username,
            'password': 'wrongpassword'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_user_profile_authenticated(self):
        self.client.force_authenticate(user=self.user)
        url = reverse('user_profile')
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], self.user.username)
    
    def test_user_profile_unauthenticated(self):
        url = reverse('user_profile')
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class AlertAPITest(APITestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.super_admin = SuperAdminFactory()
        self.sub_admin = SubAdminFactory(organization=self.organization)
        self.geofence = GeofenceFactory(organization=self.organization)
        self.alert = AlertFactory(geofence=self.geofence)
    
    def test_create_alert_super_admin(self):
        self.client.force_authenticate(user=self.super_admin)
        url = reverse('alert-list')
        data = {
            'title': 'Test Alert',
            'description': 'Test Description',
            'alert_type': 'GEOFENCE_ENTER',
            'severity': 'HIGH',
            'geofence': self.geofence.id
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Alert.objects.filter(title='Test Alert').exists())
    
    def test_create_alert_sub_admin(self):
        self.client.force_authenticate(user=self.sub_admin)
        url = reverse('alert-list')
        data = {
            'title': 'Test Alert',
            'description': 'Test Description',
            'alert_type': 'GEOFENCE_ENTER',
            'severity': 'HIGH',
            'geofence': self.geofence.id
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    
    def test_list_alerts_organization_isolation(self):
        # Create alert for different organization
        other_organization = OrganizationFactory()
        other_geofence = GeofenceFactory(organization=other_organization)
        other_alert = AlertFactory(geofence=other_geofence)
        
        self.client.force_authenticate(user=self.sub_admin)
        url = reverse('alert-list')
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Sub-admin should only see alerts from their organization
        alert_ids = [alert['id'] for alert in response.data['results']]
        self.assertIn(self.alert.id, alert_ids)
        self.assertNotIn(other_alert.id, alert_ids)
    
    def test_update_alert_resolution(self):
        self.client.force_authenticate(user=self.super_admin)
        url = reverse('alert-detail', kwargs={'pk': self.alert.pk})
        data = {
            'is_resolved': True
        }
        
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.alert.refresh_from_db()
        self.assertTrue(self.alert.is_resolved)


class ReportAPITest(APITestCase):
    def setUp(self):
        self.super_admin = SuperAdminFactory()
        self.sub_admin = SubAdminFactory()
        self.report = GlobalReportFactory(generated_by=self.super_admin)
    
    def test_create_report_super_admin(self):
        self.client.force_authenticate(user=self.super_admin)
        url = reverse('report-list')
        data = {
            'title': 'Test Report',
            'description': 'Test Description',
            'report_type': 'GEOFENCE_ANALYTICS',
            'date_range_start': '2024-01-01T00:00:00Z',
            'date_range_end': '2024-01-31T23:59:59Z'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(GlobalReport.objects.filter(title='Test Report').exists())
    
    def test_create_report_sub_admin_forbidden(self):
        self.client.force_authenticate(user=self.sub_admin)
        url = reverse('report-list')
        data = {
            'title': 'Test Report',
            'description': 'Test Description',
            'report_type': 'GEOFENCE_ANALYTICS',
            'date_range_start': '2024-01-01T00:00:00Z',
            'date_range_end': '2024-01-31T23:59:59Z'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    @patch('users.views.generate_report')
    def test_generate_report(self, mock_generate_report):
        mock_generate_report.return_value = {
            'message': 'Report generated successfully',
            'report_id': self.report.id,
            'metrics': {'test': 'data'}
        }
        
        self.client.force_authenticate(user=self.super_admin)
        url = reverse('generate_report')
        data = {
            'report_type': 'GEOFENCE_ANALYTICS',
            'date_range_start': '2024-01-01T00:00:00Z',
            'date_range_end': '2024-01-31T23:59:59Z',
            'title': 'Test Report'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    
    def test_download_report(self):
        # Mark report as generated
        self.report.mark_as_generated('/tmp/test.csv')
        
        self.client.force_authenticate(user=self.super_admin)
        url = reverse('download_report', kwargs={'report_id': self.report.id})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'text/csv')


class DashboardKPITest(APITestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.super_admin = SuperAdminFactory()
        self.sub_admin = SubAdminFactory(organization=self.organization)
        
        # Create test data
        self.geofence = GeofenceFactory(organization=self.organization)
        self.alert = AlertFactory(geofence=self.geofence, severity='CRITICAL')
    
    def test_dashboard_kpis_super_admin(self):
        self.client.force_authenticate(user=self.super_admin)
        url = reverse('dashboard_kpis')
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        kpis = response.data
        self.assertIn('active_geofences', kpis)
        self.assertIn('alerts_today', kpis)
        self.assertIn('critical_alerts', kpis)
        self.assertIn('system_health', kpis)
    
    def test_dashboard_kpis_sub_admin(self):
        self.client.force_authenticate(user=self.sub_admin)
        url = reverse('dashboard_kpis')
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        kpis = response.data
        # Sub-admin should only see KPIs for their organization
        self.assertGreaterEqual(kpis['active_geofences'], 1)  # At least their geofence


class PermissionTest(APITestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.super_admin = SuperAdminFactory()
        self.sub_admin = SubAdminFactory(organization=self.organization)
        self.regular_user = UserFactory(organization=self.organization)
    
    def test_super_admin_permissions(self):
        self.client.force_authenticate(user=self.super_admin)
        
        # Test various endpoints
        urls_to_test = [
            reverse('subadmin-list'),
            reverse('organization-list'),
            reverse('geofence-list'),
            reverse('user-list'),
            reverse('alert-list'),
            reverse('report-list'),
        ]
        
        for url in urls_to_test:
            response = self.client.get(url)
            self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_405_METHOD_NOT_ALLOWED])
    
    def test_sub_admin_permissions(self):
        self.client.force_authenticate(user=self.sub_admin)
        
        # Sub-admin should have read access to most endpoints
        read_urls = [
            reverse('geofence-list'),
            reverse('user-list'),
            reverse('alert-list'),
        ]
        
        for url in read_urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Sub-admin should not have access to reports creation
        response = self.client.post(reverse('report-list'), {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_regular_user_permissions(self):
        self.client.force_authenticate(user=self.regular_user)
        
        # Regular user should not have access to admin endpoints
        admin_urls = [
            reverse('subadmin-list'),
            reverse('organization-list'),
            reverse('geofence-list'),
            reverse('user-list'),
            reverse('alert-list'),
            reverse('report-list'),
        ]
        
        for url in admin_urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


# Integration Tests
class IntegrationTest(APITestCase):
    def setUp(self):
        self.organization = OrganizationFactory()
        self.super_admin = SuperAdminFactory()
        self.sub_admin = SubAdminFactory(organization=self.organization)
        self.geofence = GeofenceFactory(organization=self.organization)
    
    def test_complete_alert_workflow(self):
        # 1. Create alert as super admin
        self.client.force_authenticate(user=self.super_admin)
        alert_data = {
            'title': 'Integration Test Alert',
            'description': 'Test Description',
            'alert_type': 'GEOFENCE_ENTER',
            'severity': 'HIGH',
            'geofence': self.geofence.id
        }
        
        create_response = self.client.post(reverse('alert-list'), alert_data, format='json')
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        alert_id = create_response.data['id']
        
        # 2. List alerts as sub-admin (organization isolation)
        self.client.force_authenticate(user=self.sub_admin)
        list_response = self.client.get(reverse('alert-list'))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        
        # 3. Update alert resolution
        self.client.force_authenticate(user=self.super_admin)
        update_data = {'is_resolved': True}
        update_response = self.client.patch(
            reverse('alert-detail', kwargs={'pk': alert_id}),
            update_data,
            format='json'
        )
        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        
        # 4. Verify alert is resolved
        get_response = self.client.get(reverse('alert-detail', kwargs={'pk': alert_id}))
        self.assertEqual(get_response.status_code, status.HTTP_200_OK)
        self.assertTrue(get_response.data['is_resolved'])
    
    def test_complete_report_workflow(self):
        # 1. Create report
        self.client.force_authenticate(user=self.super_admin)
        report_data = {
            'title': 'Integration Test Report',
            'description': 'Test Description',
            'report_type': 'GEOFENCE_ANALYTICS',
            'date_range_start': '2024-01-01T00:00:00Z',
            'date_range_end': '2024-01-31T23:59:59Z'
        }
        
        create_response = self.client.post(reverse('report-list'), report_data, format='json')
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        report_id = create_response.data['id']
        
        # 2. Generate report
        generate_data = {
            'report_type': 'GEOFENCE_ANALYTICS',
            'date_range_start': '2024-01-01T00:00:00Z',
            'date_range_end': '2024-01-31T23:59:59Z',
            'title': 'Generated Report'
        }
        
        generate_response = self.client.post(reverse('generate_report'), generate_data, format='json')
        self.assertEqual(generate_response.status_code, status.HTTP_201_CREATED)
        
        # 3. Download report
        download_response = self.client.get(reverse('download_report', kwargs={'report_id': report_id}))
        self.assertEqual(download_response.status_code, status.HTTP_200_OK)
        self.assertEqual(download_response['Content-Type'], 'text/csv')


# Performance Tests
class PerformanceTest(APITestCase):
    def setUp(self):
        self.super_admin = SuperAdminFactory()
        self.organization = OrganizationFactory()
        
        # Create bulk data for performance testing
        self.geofences = [GeofenceFactory(organization=self.organization) for _ in range(100)]
        self.alerts = [AlertFactory(geofence=geofence) for geofence in self.geofences]
    
    def test_bulk_alert_creation_performance(self):
        self.client.force_authenticate(user=self.super_admin)
        
        import time
        start_time = time.time()
        
        for i in range(10):
            alert_data = {
                'title': f'Performance Test Alert {i}',
                'description': 'Test Description',
                'alert_type': 'GEOFENCE_ENTER',
                'severity': 'MEDIUM',
                'geofence': self.geofences[i % len(self.geofences)].id
            }
            response = self.client.post(reverse('alert-list'), alert_data, format='json')
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        self.assertLess(execution_time, 5.0)  # 5 seconds for 10 alerts
    
    def test_bulk_alert_listing_performance(self):
        self.client.force_authenticate(user=self.super_admin)
        
        import time
        start_time = time.time()
        
        response = self.client.get(reverse('alert-list'))
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should complete within reasonable time
        self.assertLess(execution_time, 2.0)  # 2 seconds for listing
