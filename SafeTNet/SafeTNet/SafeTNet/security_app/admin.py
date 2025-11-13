from django.contrib import admin
from .models import SOSAlert, Case, Incident, OfficerProfile, Notification


@admin.register(SOSAlert)
class SOSAlertAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'geofence', 'status', 'priority', 'assigned_officer', 'is_deleted', 'created_at')
    list_filter = ('status', 'priority', 'is_deleted')
    search_fields = ('user__username', 'assigned_officer__name')


@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = ('id', 'sos_alert', 'officer', 'status', 'updated_at')
    list_filter = ('status', 'officer')
    search_fields = ('sos_alert__user__username', 'officer__name', 'description')


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('id', 'officer', 'sos_alert', 'case', 'status', 'timestamp')
    list_filter = ('status', 'officer')
    search_fields = ('description', 'officer__name', 'sos_alert__user__username')


@admin.register(OfficerProfile)
class OfficerProfileAdmin(admin.ModelAdmin):
    list_display = ('officer', 'on_duty', 'updated_at')
    list_filter = ('on_duty',)


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'officer', 'title', 'notification_type', 'is_read', 'created_at')
    list_filter = ('notification_type', 'is_read', 'officer')
    search_fields = ('title', 'message', 'officer__name')
    readonly_fields = ('created_at', 'read_at')

