from rest_framework import permissions
from django.core.exceptions import PermissionDenied
import logging

logger = logging.getLogger(__name__)


class IsSuperAdmin(permissions.BasePermission):
    """
    Custom permission to only allow SUPER_ADMIN users.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            logger.warning(f"Unauthenticated access attempt to {view.__class__.__name__}")
            return False
        
        is_super_admin = request.user.role == 'SUPER_ADMIN'
        if not is_super_admin:
            logger.warning(f"Non-SUPER_ADMIN user {request.user.username} attempted access to {view.__class__.__name__}")
        
        return is_super_admin


class IsSuperAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to allow SUPER_ADMIN full access, others read-only.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            logger.warning(f"Unauthenticated access attempt to {view.__class__.__name__}")
            return False
        
        if request.method in permissions.SAFE_METHODS:
            return True
        
        is_super_admin = request.user.role == 'SUPER_ADMIN'
        if not is_super_admin:
            logger.warning(f"Non-SUPER_ADMIN user {request.user.username} attempted {request.method} on {view.__class__.__name__}")
        
        return is_super_admin


class IsSuperAdminOrSubAdmin(permissions.BasePermission):
    """
    Custom permission to allow SUPER_ADMIN and SUB_ADMIN users.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            logger.warning(f"Unauthenticated access attempt to {view.__class__.__name__}")
            return False
        
        has_access = request.user.role in ['SUPER_ADMIN', 'SUB_ADMIN']
        if not has_access:
            logger.warning(f"User {request.user.username} with role {request.user.role} attempted access to {view.__class__.__name__}")
        
        return has_access


class IsSuperAdminOrSubAdminReadOnly(permissions.BasePermission):
    """
    Custom permission to allow SUPER_ADMIN full access, SUB_ADMIN read-only.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            logger.warning(f"Unauthenticated access attempt to {view.__class__.__name__}")
            return False
        
        if request.user.role == 'SUPER_ADMIN':
            return True
        
        if request.user.role == 'SUB_ADMIN':
            if request.method in permissions.SAFE_METHODS:
                return True
            else:
                logger.warning(f"SUB_ADMIN user {request.user.username} attempted {request.method} on {view.__class__.__name__}")
                return False
        
        logger.warning(f"User {request.user.username} with role {request.user.role} attempted access to {view.__class__.__name__}")
        return False


class OrganizationIsolationMixin:
    """
    Mixin to enforce organization-based data isolation for Sub-Admins.
    """
    
    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.user
        
        # SUPER_ADMIN can see all data
        if user.role == 'SUPER_ADMIN':
            return queryset
        
        # SUB_ADMIN can only see data from their organization
        if user.role == 'SUB_ADMIN' and user.organization:
            filtered_queryset = queryset.filter(organization=user.organization)
            logger.info(f"SUB_ADMIN {user.username} accessing organization-filtered data: {filtered_queryset.count()} records")
            return filtered_queryset
        
        # Regular users see no data (should not reach here with proper permissions)
        logger.warning(f"User {user.username} with role {user.role} accessing data without proper organization")
        return queryset.none()


class ResourceOwnershipMixin:
    """
    Mixin to enforce resource ownership for certain operations.
    """
    
    def get_object(self):
        obj = super().get_object()
        user = self.request.user
        
        # SUPER_ADMIN can access all resources
        if user.role == 'SUPER_ADMIN':
            return obj
        
        # SUB_ADMIN can only access resources from their organization
        if user.role == 'SUB_ADMIN' and user.organization:
            if hasattr(obj, 'organization') and obj.organization != user.organization:
                logger.warning(f"SUB_ADMIN {user.username} attempted to access resource from different organization")
                raise PermissionDenied("You don't have permission to access this resource.")
            return obj
        
        logger.warning(f"User {user.username} with role {user.role} attempted unauthorized resource access")
        raise PermissionDenied("You don't have permission to access this resource.")
