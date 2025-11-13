from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
import json
import logging

logger = logging.getLogger(__name__)


class Organization(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'


class User(AbstractUser):
    ROLE_CHOICES = [
        ('SUPER_ADMIN', 'Super Admin'),
        ('SUB_ADMIN', 'Sub Admin'),
        ('USER', 'User'),
    ]
    
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='USER'
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.username} ({self.role})"


class Geofence(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    polygon_json = models.JSONField(help_text="GeoJSON polygon coordinates")
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='geofences'
    )
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_geofences'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Geofence'
        verbose_name_plural = 'Geofences'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.organization.name})"
    
    def get_polygon_coordinates(self):
        """Extract coordinates from GeoJSON polygon"""
        try:
            if isinstance(self.polygon_json, dict):
                if self.polygon_json.get('type') == 'Polygon':
                    return self.polygon_json.get('coordinates', [])
                elif self.polygon_json.get('type') == 'Feature':
                    geometry = self.polygon_json.get('geometry', {})
                    if geometry.get('type') == 'Polygon':
                        return geometry.get('coordinates', [])
            return []
        except (json.JSONDecodeError, AttributeError):
            return []
    
    def get_center_point(self):
        """Calculate center point of the polygon"""
        coordinates = self.get_polygon_coordinates()
        if not coordinates or not coordinates[0]:
            return None
        
        # Get the first ring of the polygon
        ring = coordinates[0]
        if not ring:
            return None
        
        # Calculate center
        # GeoJSON format is [longitude, latitude], so coord[0] is lon, coord[1] is lat
        lats = [coord[1] for coord in ring]
        lons = [coord[0] for coord in ring]
        
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)
        
        # Return as [latitude, longitude] for frontend compatibility
        return [center_lat, center_lon]


class Alert(models.Model):
    ALERT_TYPES = [
        ('GEOFENCE_ENTER', 'Geofence Enter'),
        ('GEOFENCE_EXIT', 'Geofence Exit'),
        ('GEOFENCE_VIOLATION', 'Geofence Violation'),
        ('SYSTEM_ERROR', 'System Error'),
        ('SECURITY_BREACH', 'Security Breach'),
        ('MAINTENANCE', 'Maintenance'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    geofence = models.ForeignKey(
        Geofence,
        on_delete=models.CASCADE,
        related_name='alerts',
        null=True,
        blank=True
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='alerts',
        null=True,
        blank=True
    )
    alert_type = models.CharField(
        max_length=20,
        choices=ALERT_TYPES,
        default='GEOFENCE_ENTER'
    )
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='MEDIUM'
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    metadata = models.JSONField(default=dict, blank=True)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_alerts'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} ({self.severity})"
    
    def resolve(self, resolved_by_user):
        """Mark alert as resolved"""
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.resolved_by = resolved_by_user
        self.save()


class SecurityOfficer(models.Model):
    username = models.CharField(max_length=150, unique=True, blank=True, null=True, help_text="Unique username for security officer")
    name = models.CharField(max_length=100)
    contact = models.CharField(max_length=20, help_text="Phone number or contact info")
    email = models.EmailField(blank=True, null=True)
    password = models.CharField(max_length=128, blank=True, null=True, help_text="Hashed password for security officer")
    assigned_geofence = models.ForeignKey(
        Geofence,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_officers'
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='security_officers'
    )
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_officers',
        limit_choices_to={'role': 'SUB_ADMIN'}
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Security Officer'
        verbose_name_plural = 'Security Officers'
        ordering = ['-created_at']
    
    def set_password(self, raw_password):
        """Hash and set password"""
        from django.contrib.auth.hashers import make_password
        self.password = make_password(raw_password)
    
    def check_password(self, raw_password):
        """Check if the provided password is correct"""
        from django.contrib.auth.hashers import check_password
        return check_password(raw_password, self.password)
    
    def __str__(self):
        return f"{self.name} ({self.organization.name})"


class Incident(models.Model):
    INCIDENT_TYPES = [
        ('SECURITY_BREACH', 'Security Breach'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
        ('EMERGENCY', 'Emergency'),
        ('MAINTENANCE', 'Maintenance'),
        ('OTHER', 'Other'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    geofence = models.ForeignKey(
        Geofence,
        on_delete=models.CASCADE,
        related_name='incidents'
    )
    officer = models.ForeignKey(
        SecurityOfficer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reported_incidents'
    )
    incident_type = models.CharField(
        max_length=20,
        choices=INCIDENT_TYPES,
        default='SUSPICIOUS_ACTIVITY'
    )
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='MEDIUM'
    )
    title = models.CharField(max_length=200)
    details = models.TextField()
    location = models.JSONField(
        default=dict,
        help_text="GPS coordinates and location details"
    )
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_incidents'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Incident'
        verbose_name_plural = 'Incidents'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} ({self.severity})"
    
    def resolve(self, resolved_by_user):
        """Mark incident as resolved"""
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.resolved_by = resolved_by_user
        self.save()


class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('NORMAL', 'Normal'),
        ('EMERGENCY', 'Emergency'),
    ]
    
    TARGET_TYPES = [
        ('ALL_OFFICERS', 'All Officers'),
        ('GEOFENCE_OFFICERS', 'Geofence Officers'),
        ('SPECIFIC_OFFICERS', 'Specific Officers'),
        ('SUB_ADMIN', 'Sub Admin Only'),
    ]
    
    notification_type = models.CharField(
        max_length=10,
        choices=NOTIFICATION_TYPES,
        default='NORMAL'
    )
    title = models.CharField(max_length=200)
    message = models.TextField()
    target_type = models.CharField(
        max_length=20,
        choices=TARGET_TYPES,
        default='ALL_OFFICERS'
    )
    target_geofence = models.ForeignKey(
        Geofence,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='notifications'
    )
    target_geofences = models.JSONField(
        default=list,
        blank=True,
        help_text='List of geofence IDs for multi-geofence notifications'
    )
    target_officers = models.ManyToManyField(
        SecurityOfficer,
        blank=True,
        related_name='received_notifications'
    )
    read_users = models.ManyToManyField(
        User,
        blank=True,
        related_name='read_notifications',
        help_text='Users who have read this notification'
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    is_sent = models.BooleanField(default=False)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_notifications',
        limit_choices_to={'role': 'SUB_ADMIN'}
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Notification'
        verbose_name_plural = 'Notifications'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} ({self.notification_type})"
    
    def mark_as_sent(self):
        """Mark notification as sent"""
        self.is_sent = True
        self.sent_at = timezone.now()
        self.save()


class GlobalReport(models.Model):
    REPORT_TYPES = [
        ('GEOFENCE_ANALYTICS', 'Geofence Analytics'),
        ('USER_ACTIVITY', 'User Activity'),
        ('ALERT_SUMMARY', 'Alert Summary'),
        ('SYSTEM_HEALTH', 'System Health'),
        ('CUSTOM', 'Custom Report'),
    ]
    
    report_type = models.CharField(
        max_length=20,
        choices=REPORT_TYPES,
        default='GEOFENCE_ANALYTICS'
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    date_range_start = models.DateTimeField()
    date_range_end = models.DateTimeField()
    metrics = models.JSONField(default=dict)
    file_path = models.CharField(max_length=500, blank=True, null=True)
    generated_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='generated_reports'
    )
    is_generated = models.BooleanField(default=False)
    generated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Global Report'
        verbose_name_plural = 'Global Reports'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.title} ({self.report_type})"
    
    def mark_as_generated(self, file_path=None):
        """Mark report as generated"""
        self.is_generated = True
        self.generated_at = timezone.now()
        if file_path:
            self.file_path = file_path
        self.save()


class PromoCode(models.Model):
    code = models.CharField(max_length=50, unique=True, help_text="Unique promo code")
    discount_percentage = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Discount percentage (0-100)"
    )
    expiry_date = models.DateTimeField(help_text="Expiry date and time for the promo code")
    is_active = models.BooleanField(default=True, help_text="Whether the promo code is active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Promo Code'
        verbose_name_plural = 'Promo Codes'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.code} ({self.discount_percentage}%)"
    
    def is_valid(self):
        """Check if promo code is valid (active and not expired)"""
        return self.is_active and timezone.now() < self.expiry_date


class DiscountEmail(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('SENT', 'Sent'),
    ]
    
    email = models.EmailField(help_text="Email address to send discount to")
    discount_code = models.ForeignKey(
        PromoCode,
        on_delete=models.CASCADE,
        related_name='discount_emails',
        help_text="Promo code to send"
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='PENDING',
        help_text="Status of the discount email"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Discount Email'
        verbose_name_plural = 'Discount Emails'
        ordering = ['-created_at']
        unique_together = ['email', 'discount_code']
    
    def __str__(self):
        return f"{self.email} - {self.discount_code.code} ({self.status})"
    
    def mark_as_sent(self):
        """Mark discount email as sent"""
        self.status = 'SENT'
        self.save()
    
    def send_email(self):
        """Send discount email to user"""
        from django.core.mail import send_mail
        from django.conf import settings
        from django.template.loader import render_to_string
        
        try:
            subject = f"Special Discount Code: {self.discount_code.code}"
            
            # Create email message with discount details
            message = f"""
Hello,

We're excited to offer you an exclusive discount!

Use code: {self.discount_code.code}
Discount: {self.discount_code.discount_percentage}% OFF

This discount code expires on: {self.discount_code.expiry_date.strftime('%B %d, %Y at %I:%M %p')}

Thank you for being part of SafeTNet!

Best regards,
The SafeTNet Team
            """
            
            # Send email
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[self.email],
                fail_silently=False,
            )
            
            # Mark as sent
            self.mark_as_sent()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send discount email to {self.email}: {str(e)}")
            return False


class UserReply(models.Model):
    email = models.EmailField(help_text="Email address of the user who replied")
    message = models.TextField(help_text="Reply message from the user")
    date_time = models.DateTimeField(auto_now_add=True, help_text="Date and time when the reply was received")
    
    class Meta:
        verbose_name = 'User Reply'
        verbose_name_plural = 'User Replies'
        ordering = ['-date_time']
    
    def __str__(self):
        return f"{self.email} - {self.date_time.strftime('%Y-%m-%d %H:%M')}"


class PasswordResetOTP(models.Model):
    """Model to store OTP for password reset"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_otps')
    otp = models.CharField(max_length=6, help_text="6-digit OTP code")
    email = models.EmailField(help_text="Email address for verification")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="OTP expiration time")
    is_used = models.BooleanField(default=False, help_text="Whether OTP has been used")
    
    class Meta:
        verbose_name = 'Password Reset OTP'
        verbose_name_plural = 'Password Reset OTPs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"OTP for {self.email} - {self.otp}"
    
    def is_valid(self):
        """Check if OTP is valid (not used and not expired)"""
        return not self.is_used and timezone.now() < self.expires_at


class UserDetails(models.Model):
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('SUSPENDED', 'Suspended'),
    ]
    
    username = models.CharField(max_length=150, unique=True, help_text="Username of the user")
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Price associated with the user")
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='ACTIVE',
        help_text="Status of the user"
    )
    date = models.DateTimeField(auto_now_add=True, help_text="Date when the user details were created")
    
    class Meta:
        verbose_name = 'User Detail'
        verbose_name_plural = 'User Details'
        ordering = ['-date']
    
    def __str__(self):
        return f"{self.username} - {self.status} (${self.price})"