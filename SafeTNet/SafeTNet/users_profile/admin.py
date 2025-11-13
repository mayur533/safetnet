"""
Django admin configuration for users_profile models.
Avoid registering the User model here because it is already registered in `users/admin.py`.
"""
from django.contrib import admin
from .models import FamilyContact, CommunityMembership, SOSEvent


@admin.register(FamilyContact)
class FamilyContactAdmin(admin.ModelAdmin):
    """
    Admin configuration for FamilyContact model.
    """
    list_display = ('name', 'phone', 'relationship', 'user', 'is_primary', 'created_at')
    list_filter = ('is_primary', 'relationship', 'created_at')
    search_fields = ('name', 'phone', 'user__name', 'user__email')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('user', 'name', 'phone', 'relationship')}),
        ('Settings', {'fields': ('is_primary',)}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )
    
    readonly_fields = ('created_at', 'updated_at')
    
    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')


@admin.register(CommunityMembership)
class CommunityMembershipAdmin(admin.ModelAdmin):
    """
    Admin configuration for CommunityMembership model.
    """
    list_display = ('user', 'community_name', 'community_id', 'is_active', 'joined_at')
    list_filter = ('is_active', 'joined_at')
    search_fields = ('user__name', 'user__email', 'community_name', 'community_id')
    ordering = ('-joined_at',)
    
    fieldsets = (
        (None, {'fields': ('user', 'community_id', 'community_name')}),
        ('Status', {'fields': ('is_active',)}),
        ('Timestamps', {'fields': ('joined_at',)}),
    )
    
    readonly_fields = ('joined_at',)
    
    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')


@admin.register(SOSEvent)
class SOSEventAdmin(admin.ModelAdmin):  # Removed OSMGeoAdmin inheritance
    """
    Admin configuration for SOSEvent model.
    """
    list_display = ('user', 'status', 'triggered_at', 'resolved_at', 'location_display')
    list_filter = ('status', 'triggered_at', 'resolved_at')
    search_fields = ('user__name', 'user__email', 'notes')
    ordering = ('-triggered_at',)
    
    fieldsets = (
        (None, {'fields': ('user', 'status', 'notes')}),
        ('Location', {'fields': ('location',)}),
        ('Timestamps', {'fields': ('triggered_at', 'resolved_at')}),
    )
    
    readonly_fields = ('triggered_at',)
    
    def location_display(self, obj):
        """Display location coordinates for JSONField location."""
        if obj.location and isinstance(obj.location, dict):
            lat = obj.location.get('latitude')
            lon = obj.location.get('longitude')
            if lat is not None and lon is not None:
                try:
                    return f"{float(lat):.6f}, {float(lon):.6f}"
                except (TypeError, ValueError):
                    return f"{lat}, {lon}"
        return "No location"
    location_display.short_description = 'Location'
    
    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')
    
    def has_add_permission(self, request):
        """Prevent manual creation of SOS events."""
        return False


# Customize admin site
admin.site.site_header = "Safe-T-Net Administration"
admin.site.site_title = "Safe-T-Net Admin"
admin.site.index_title = "Welcome to Safe-T-Net Administration"
