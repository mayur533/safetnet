from rest_framework.permissions import BasePermission
from django.core.exceptions import ObjectDoesNotExist
from users.models import SecurityOfficer


class IsSecurityOfficer(BasePermission):
    message = 'Only security officers can access this resource.'

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        role_value = str(getattr(user, 'role', '') or '').lower()
        # Accept canonical 'security' and legacy 'security_officer'
        if role_value in ('security', 'security_officer'):
            return True
        # Fallback: if user corresponds to a SecurityOfficer by email
        try:
            if getattr(user, 'email', None):
                SecurityOfficer.objects.get(email=user.email)
                return True
        except (ObjectDoesNotExist, SecurityOfficer.DoesNotExist):
            pass
        return False

