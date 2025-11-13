from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = 'List all users with usernames formatted for reference'

    def handle(self, *args, **options):
        users = User.objects.all().order_by('username').select_related('organization')
        
        self.stdout.write(self.style.SUCCESS('\n=== COMPLETE USER LIST ===\n'))
        self.stdout.write(f'Total users found: {users.count()}\n')
        self.stdout.write('=' * 120)
        self.stdout.write(f'{"#":<4} {"Username":<25} {"Email":<30} {"Role":<15} {"Organization":<30}')
        self.stdout.write('=' * 120)
        
        user_number = 1
        for user in users:
            org_name = user.organization.name if user.organization else 'None'
            email = user.email or 'N/A'
            org_display = org_name[:28] if len(org_name) > 28 else org_name
            email_display = email[:28] if len(email) > 28 else email
            
            self.stdout.write(
                f'{user_number:<4} '
                f'{user.username:<25} '
                f'{email_display:<30} '
                f'{user.role:<15} '
                f'{org_display:<30}'
            )
            user_number += 1
        
        self.stdout.write('=' * 120)
        self.stdout.write(self.style.WARNING('\n⚠️  IMPORTANT: Passwords are hashed in the database and cannot be retrieved.'))
        self.stdout.write(self.style.WARNING('   To get working passwords, you must reset them using Django admin or a reset script.\n'))
        self.stdout.write(self.style.SUCCESS(f'\nTotal: {users.count()} users listed\n'))

