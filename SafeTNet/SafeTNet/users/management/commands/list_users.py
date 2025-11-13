from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from users.models import Organization

User = get_user_model()


class Command(BaseCommand):
    help = 'List all users with their usernames and information'

    def add_arguments(self, parser):
        parser.add_argument(
            '--with-passwords',
            action='store_true',
            help='Show password hashes (for reference only - passwords are hashed)'
        )

    def handle(self, *args, **options):
        users = User.objects.all().order_by('username').select_related('organization')
        
        self.stdout.write(self.style.SUCCESS('\n=== USER LIST ===\n'))
        
        if not users.exists():
            self.stdout.write(self.style.WARNING('No users found in database.'))
            return
        
        self.stdout.write(f'Total users: {users.count()}\n')
        self.stdout.write('-' * 100)
        
        for user in users:
            org_name = user.organization.name if user.organization else 'None'
            
            self.stdout.write(f'\nUsername: {self.style.SUCCESS(user.username)}')
            self.stdout.write(f'  ID: {user.id}')
            self.stdout.write(f'  Email: {user.email}')
            self.stdout.write(f'  Full Name: {user.first_name} {user.last_name}')
            self.stdout.write(f'  Role: {self.style.WARNING(user.role)}')
            self.stdout.write(f'  Organization: {org_name}')
            self.stdout.write(f'  Active: {"Yes" if user.is_active else "No"}')
            self.stdout.write(f'  Staff: {"Yes" if user.is_staff else "No"}')
            self.stdout.write(f'  Date Joined: {user.date_joined.strftime("%Y-%m-%d %H:%M:%S") if user.date_joined else "N/A"}')
            self.stdout.write(f'  Last Login: {user.last_login.strftime("%Y-%m-%d %H:%M:%S") if user.last_login else "Never"}')
            
            if options['with_passwords']:
                self.stdout.write(f'  Password Hash: {user.password[:50]}...')
            
            self.stdout.write('-' * 100)
        
        self.stdout.write(self.style.SUCCESS(f'\n=== END OF LIST ({users.count()} users) ===\n'))

