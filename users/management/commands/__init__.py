from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction
import json
import os

User = get_user_model()


class Command(BaseCommand):
    help = 'Load initial seed data for SafeTNet Admin Panel'

    def add_arguments(self, parser):
        parser.add_argument(
            '--file',
            type=str,
            default='initial_data.json',
            help='Path to the JSON file containing seed data'
        )
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset existing data before loading seed data'
        )

    def handle(self, *args, **options):
        file_path = options['file']
        reset = options['reset']

        if not os.path.exists(file_path):
            self.stdout.write(
                self.style.ERROR(f'File {file_path} not found')
            )
            return

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            if reset:
                self.stdout.write('Resetting existing data...')
                self.reset_data()

            self.stdout.write('Loading seed data...')
            self.load_data(data)

            self.stdout.write(
                self.style.SUCCESS('Successfully loaded seed data!')
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error loading seed data: {str(e)}')
            )

    def reset_data(self):
        """Reset existing data"""
        from users.models import Alert, GlobalReport, Geofence, Organization
        
        # Delete in reverse order of dependencies
        Alert.objects.all().delete()
        GlobalReport.objects.all().delete()
        Geofence.objects.all().delete()
        User.objects.filter(is_superuser=False).delete()
        Organization.objects.all().delete()

    def load_data(self, data):
        """Load data from JSON"""
        with transaction.atomic():
            for item in data:
                model_name = item['model']
                fields = item['fields']
                pk = item['pk']

                if model_name == 'users.organization':
                    self.create_organization(pk, fields)
                elif model_name == 'users.user':
                    self.create_user(pk, fields)
                elif model_name == 'users.geofence':
                    self.create_geofence(pk, fields)
                elif model_name == 'users.alert':
                    self.create_alert(pk, fields)
                elif model_name == 'users.globalreport':
                    self.create_report(pk, fields)

    def create_organization(self, pk, fields):
        """Create organization"""
        from users.models import Organization
        
        org, created = Organization.objects.get_or_create(
            id=pk,
            defaults={
                'name': fields['name'],
                'description': fields['description']
            }
        )
        
        if created:
            self.stdout.write(f'Created organization: {org.name}')
        else:
            self.stdout.write(f'Organization already exists: {org.name}')

    def create_user(self, pk, fields):
        """Create user"""
        from users.models import Organization
        
        # Get organization if specified
        organization = None
        if fields.get('organization'):
            try:
                organization = Organization.objects.get(id=fields['organization'])
            except Organization.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'Organization {fields["organization"]} not found for user {fields["username"]}')
                )

        user, created = User.objects.get_or_create(
            id=pk,
            defaults={
                'username': fields['username'],
                'email': fields['email'],
                'first_name': fields['first_name'],
                'last_name': fields['last_name'],
                'role': fields['role'],
                'organization': organization,
                'is_active': fields['is_active'],
                'is_staff': fields['is_staff']
            }
        )

        if created:
            # Set password
            user.set_password('testpass123!')
            user.save()
            self.stdout.write(f'Created user: {user.username}')
        else:
            self.stdout.write(f'User already exists: {user.username}')

    def create_geofence(self, pk, fields):
        """Create geofence"""
        from users.models import Organization
        from django.utils.dateparse import parse_datetime
        
        # Get organization
        try:
            organization = Organization.objects.get(id=fields['organization'])
        except Organization.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f'Organization {fields["organization"]} not found for geofence {fields["name"]}')
            )
            return

        geofence, created = Geofence.objects.get_or_create(
            id=pk,
            defaults={
                'name': fields['name'],
                'description': fields['description'],
                'latitude': fields['latitude'],
                'longitude': fields['longitude'],
                'radius': fields['radius'],
                'active': fields['active'],
                'organization': organization
            }
        )

        if created:
            self.stdout.write(f'Created geofence: {geofence.name}')
        else:
            self.stdout.write(f'Geofence already exists: {geofence.name}')

    def create_alert(self, pk, fields):
        """Create alert"""
        from users.models import Geofence, Organization
        from django.utils.dateparse import parse_datetime
        
        # Get geofence if specified
        geofence = None
        if fields.get('geofence'):
            try:
                geofence = Geofence.objects.get(id=fields['geofence'])
            except Geofence.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'Geofence {fields["geofence"]} not found for alert {fields["title"]}')
                )

        # Get user if specified
        user = None
        if fields.get('user'):
            try:
                user = User.objects.get(id=fields['user'])
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'User {fields["user"]} not found for alert {fields["title"]}')
                )

        # Get resolved_by if specified
        resolved_by = None
        if fields.get('resolved_by'):
            try:
                resolved_by = User.objects.get(id=fields['resolved_by'])
            except User.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(f'Resolved by user {fields["resolved_by"]} not found for alert {fields["title"]}')
                )

        alert, created = Alert.objects.get_or_create(
            id=pk,
            defaults={
                'title': fields['title'],
                'description': fields['description'],
                'alert_type': fields['alert_type'],
                'severity': fields['severity'],
                'metadata': fields['metadata'],
                'is_resolved': fields['is_resolved'],
                'geofence': geofence,
                'user': user,
                'resolved_by': resolved_by
            }
        )

        if created:
            self.stdout.write(f'Created alert: {alert.title}')
        else:
            self.stdout.write(f'Alert already exists: {alert.title}')

    def create_report(self, pk, fields):
        """Create global report"""
        from django.utils.dateparse import parse_datetime
        
        # Get generated_by user
        try:
            generated_by = User.objects.get(id=fields['generated_by'])
        except User.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f'Generated by user {fields["generated_by"]} not found for report {fields["title"]}')
            )
            return

        report, created = GlobalReport.objects.get_or_create(
            id=pk,
            defaults={
                'title': fields['title'],
                'description': fields['description'],
                'report_type': fields['report_type'],
                'date_range_start': parse_datetime(fields['date_range_start']),
                'date_range_end': parse_datetime(fields['date_range_end']),
                'metrics': fields['metrics'],
                'file_path': fields.get('file_path'),
                'is_generated': fields['is_generated'],
                'generated_by': generated_by
            }
        )

        if created:
            self.stdout.write(f'Created report: {report.title}')
        else:
            self.stdout.write(f'Report already exists: {report.title}')
