from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from users.models import Alert, Geofence, Organization, User
from django.db import transaction


class Command(BaseCommand):
    help = 'Add sample alerts of different types to the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=20,
            help='Number of alerts to create'
        )

    def handle(self, *args, **options):
        count = options['count']
        
        try:
            with transaction.atomic():
                alerts_created = self.create_sample_alerts(count)
                
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully created {alerts_created} sample alerts!')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating sample alerts: {str(e)}')
            )

    def create_sample_alerts(self, count):
        """Create sample alerts"""
        alerts_created = 0
        
        # Get some existing data
        organizations = list(Organization.objects.all())
        geofences = list(Geofence.objects.all())
        users = list(User.objects.filter(role='USER'))
        
        if not organizations:
            self.stdout.write(
                self.style.WARNING('No organizations found. Please create organizations first.')
            )
            return 0
        
        if not geofences:
            self.stdout.write(
                self.style.WARNING('No geofences found. Please create geofences first.')
            )
            return 0
        
        if not users:
            self.stdout.write(
                self.style.WARNING('No users found. Please create users first.')
            )
            return 0

        # Different alert types and severities
        alert_types = [
            'GEOFENCE_ENTER',
            'GEOFENCE_EXIT',
            'GEOFENCE_VIOLATION',
            'SYSTEM_ERROR',
            'SECURITY_BREACH',
            'MAINTENANCE',
        ]
        
        severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        alert_titles = [
            'User entered geofence area',
            'User exited geofence area',
            'Unauthorized access detected',
            'System performance degraded',
            'Security breach alert',
            'Maintenance scheduled',
            'Critical system error',
            'Geofence boundary violation',
            'User location update failed',
            'Network connectivity issue',
        ]
        
        now = timezone.now()
        
        for i in range(count):
            # Randomize alert properties
            import random
            alert_type = random.choice(alert_types)
            severity = random.choice(severities)
            title = random.choice(alert_titles)
            geofence = random.choice(geofences) if geofences else None
            user = random.choice(users) if users else None
            
            # Create alerts at different times (last 30 days)
            days_ago = random.randint(0, 30)
            created_at = now - timedelta(days=days_ago)
            
            # Some alerts are resolved
            is_resolved = random.choice([True, False])
            resolved_at = None
            if is_resolved:
                # resolved_at should be after created_at and before now
                resolved_days_ago = random.randint(0, days_ago)
                resolved_at = now - timedelta(days=resolved_days_ago)
            
            alert = Alert.objects.create(
                title=f"{title} #{i+1}",
                description=f"Sample alert of type {alert_type} with {severity} severity",
                alert_type=alert_type,
                severity=severity,
                geofence=geofence,
                user=user,
                is_resolved=is_resolved,
                metadata={
                    'source': 'sample_data',
                    'priority': severity,
                    'alert_id': f'ALERT-{i+1}',
                },
            )
            
            # Update timestamps after creation to override Django's auto-timestamps
            alert.created_at = created_at
            alert.resolved_at = resolved_at if is_resolved else None
            alert.save()
            
            alerts_created += 1
            
        return alerts_created

