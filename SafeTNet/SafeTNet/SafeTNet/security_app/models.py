from django.db import models
from django.contrib.auth import get_user_model
from users.models import Geofence, SecurityOfficer


User = get_user_model()


class SOSAlert(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('resolved', 'Resolved'),
    ]

    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='security_app_sos_alerts'
    )
    geofence = models.ForeignKey(
        Geofence,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='sos_alerts'
    )
    location_lat = models.FloatField()
    location_long = models.FloatField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    assigned_officer = models.ForeignKey(
        SecurityOfficer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_security_app_alerts'
    )
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'SOS Alert'
        verbose_name_plural = 'SOS Alerts'

    def __str__(self):
        return f"SOSAlert #{self.id} ({self.status})"


class Case(models.Model):
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('accepted', 'Accepted'),
        ('resolved', 'Resolved'),
    ]

    sos_alert = models.ForeignKey(
        SOSAlert,
        on_delete=models.CASCADE,
        related_name='cases'
    )
    officer = models.ForeignKey(
        SecurityOfficer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_cases'
    )
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='open')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'Case'
        verbose_name_plural = 'Cases'

    def __str__(self):
        return f"Case #{self.id} for SOS {self.sos_alert_id} [{self.status}]"


class OfficerProfile(models.Model):
    """Lightweight profile for security officer runtime attributes."""
    officer = models.OneToOneField(
        SecurityOfficer,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    on_duty = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile({self.officer.name}) on_duty={self.on_duty}"


class Incident(models.Model):
    STATUS_CHOICES = [
        ('resolved', 'Resolved'),
        ('manual', 'Manual'),
    ]

    officer = models.ForeignKey(
        SecurityOfficer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='incidents'
    )
    sos_alert = models.ForeignKey(
        SOSAlert,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='incidents'
    )
    case = models.ForeignKey(
        Case,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='incidents'
    )
    description = models.TextField(blank=True, null=True)
    location_lat = models.FloatField(blank=True, null=True)
    location_long = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='resolved')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Incident'
        verbose_name_plural = 'Incidents'

    def __str__(self):
        return f"Incident #{self.id} ({self.status})"


class Notification(models.Model):
    TYPE_CHOICES = [
        ('sos_alert', 'SOS Alert'),
        ('case_assigned', 'Case Assigned'),
        ('case_resolved', 'Case Resolved'),
        ('system', 'System'),
    ]

    officer = models.ForeignKey(
        SecurityOfficer,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    title = models.CharField(max_length=200)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='system')
    is_read = models.BooleanField(default=False)
    sos_alert = models.ForeignKey(
        SOSAlert,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Notification'
        verbose_name_plural = 'Notifications'

    def __str__(self):
        return f"Notification for {self.officer.name}: {self.title}"

    def mark_as_read(self):
        from django.utils import timezone
        self.is_read = True
        self.read_at = timezone.now()
        self.save(update_fields=['is_read', 'read_at'])
