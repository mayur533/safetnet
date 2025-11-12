from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = 'Reset passwords only for USER role, keep ADMIN and SUB_ADMIN passwords unchanged'

    def add_arguments(self, parser):
        parser.add_argument(
            '--password',
            type=str,
            default='testpass123!',
            help='Password to set for USER role users (default: testpass123!)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be reset without actually resetting'
        )

    def handle(self, *args, **options):
        password = options['password']
        dry_run = options['dry_run']
        
        all_users = User.objects.all().order_by('username').select_related('organization')
        user_role_users = User.objects.filter(role='USER').order_by('username').select_related('organization')
        
        if dry_run:
            self.stdout.write(self.style.WARNING('\n=== DRY RUN MODE - No passwords will be changed ===\n'))
        else:
            self.stdout.write(self.style.SUCCESS(f'\n=== Resetting passwords for USER role only ===\n'))
            self.stdout.write(self.style.WARNING(f'Password will be set to: {password}\n'))
            self.stdout.write(self.style.WARNING('⚠️  SUPER_ADMIN and SUB_ADMIN passwords will NOT be changed\n'))
        
        self.stdout.write(f'Total users: {all_users.count()}')
        self.stdout.write(f'USER role users: {user_role_users.count()}')
        self.stdout.write(f'ADMIN/SUB_ADMIN users: {all_users.count() - user_role_users.count()} (passwords unchanged)\n')
        self.stdout.write('-' * 120)
        
        user_list = []
        reset_count = 0
        
        for user in all_users:
            org_name = user.organization.name if user.organization else 'None'
            is_user_role = user.role == 'USER'
            
            if is_user_role:
                if not dry_run:
                    user.set_password(password)
                    user.save()
                    reset_count += 1
                user_password = password
                password_status = self.style.SUCCESS('RESET')
            else:
                user_password = '[UNCHANGED]'
                password_status = self.style.WARNING('KEPT AS IS')
            
            user_info = {
                'username': user.username,
                'email': user.email,
                'password': user_password,
                'role': user.role,
                'organization': org_name,
                'full_name': f'{user.first_name} {user.last_name}'.strip() or 'N/A',
                'password_changed': is_user_role
            }
            user_list.append(user_info)
            
            self.stdout.write(f'\nUsername: {self.style.SUCCESS(user.username)}')
            self.stdout.write(f'  Password: {self.style.WARNING(user_password)} {password_status}')
            self.stdout.write(f'  Email: {user.email or "N/A"}')
            self.stdout.write(f'  Full Name: {user_info["full_name"]}')
            self.stdout.write(f'  Role: {self.style.WARNING(user.role)}')
            self.stdout.write(f'  Organization: {org_name}')
            self.stdout.write('-' * 120)
        
        # Create summary table
        self.stdout.write(self.style.SUCCESS('\n\n=== SUMMARY TABLE ===\n'))
        self.stdout.write(f'{"Username":<25} {"Password":<25} {"Role":<15} {"Organization":<30}')
        self.stdout.write('-' * 120)
        
        for user_info in user_list:
            org_display = user_info['organization'][:28] if len(user_info['organization']) > 28 else user_info['organization']
            password_display = user_info['password'][:23] if len(user_info['password']) > 23 else user_info['password']
            
            self.stdout.write(
                f'{user_info["username"]:<25} '
                f'{password_display:<25} '
                f'{user_info["role"]:<15} '
                f'{org_display:<30}'
            )
        
        if not dry_run:
            self.stdout.write(self.style.SUCCESS(f'\n\n✓ Successfully reset passwords for {reset_count} USER role users\n'))
            self.stdout.write(self.style.SUCCESS(f'✓ Kept passwords unchanged for {all_users.count() - reset_count} ADMIN/SUB_ADMIN users\n'))
            self.stdout.write(self.style.WARNING(f'Note: USER role users now have password: {password}'))
        else:
            self.stdout.write(self.style.WARNING('\n\nRun without --dry-run to actually reset passwords\n'))

