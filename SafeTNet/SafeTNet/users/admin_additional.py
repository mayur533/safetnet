from django.contrib import admin
from .models import Alert, GlobalReport


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'alert_type', 'severity', 'is_resolved', 'created_at')
    list_filter = ('alert_type', 'severity', 'is_resolved', 'created_at')
    search_fields = ('title', 'description', 'user__username', 'geofence__name')
    readonly_fields = ('created_at', 'updated_at', 'resolved_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Alert Information', {
            'fields': ('title', 'description', 'alert_type', 'severity', 'metadata')
        }),
        ('Related Objects', {
            'fields': ('geofence', 'user')
        }),
        ('Resolution', {
            'fields': ('is_resolved', 'resolved_at', 'resolved_by')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(GlobalReport)
class GlobalReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'report_type', 'is_generated', 'generated_by', 'created_at')
    list_filter = ('report_type', 'is_generated', 'created_at')
    search_fields = ('title', 'description', 'generated_by__username')
    readonly_fields = ('created_at', 'updated_at', 'generated_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        ('Report Information', {
            'fields': ('title', 'description', 'report_type')
        }),
        ('Date Range', {
            'fields': ('date_range_start', 'date_range_end')
        }),
        ('Generation', {
            'fields': ('is_generated', 'generated_at', 'file_path', 'generated_by')
        }),
        ('Metrics', {
            'fields': ('metrics',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
