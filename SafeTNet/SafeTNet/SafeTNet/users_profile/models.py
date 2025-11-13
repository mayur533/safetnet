"""
Simplified user-related models; rely on the project's AUTH_USER_MODEL.
"""
from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth import get_user_model

User = get_user_model()




class FamilyContact(models.Model):
    """
    Family contact model for storing emergency contacts.
    Each user can have up to 3 family contacts.
    """
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='family_contacts',
        help_text="User who owns this family contact"
    )
    name = models.CharField(
        max_length=150,
        help_text="Family contact's name"
    )
    phone = models.CharField(
        max_length=15,
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )],
        help_text="Family contact's phone number"
    )
    relationship = models.CharField(
        max_length=50,
        blank=True,
        help_text="Relationship to the user (e.g., 'Spouse', 'Parent', 'Sibling')"
    )
    is_primary = models.BooleanField(
        default=False,
        help_text="Whether this is the primary emergency contact"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'users_family_contact'
        verbose_name = 'Family Contact'
        verbose_name_plural = 'Family Contacts'
        unique_together = ['user', 'phone']  # Prevent duplicate phone numbers per user
    
    def __str__(self):
        return f"{self.name} ({self.phone}) - {self.user.name}"
    
    def save(self, *args, **kwargs):
        # Ensure only one primary contact per user
        if self.is_primary:
            FamilyContact.objects.filter(
                user=self.user,
                is_primary=True
            ).exclude(id=self.id).update(is_primary=False)
        
        # Ensure maximum 3 contacts per user
        if not self.pk:  # Only check on creation
            if FamilyContact.objects.filter(user=self.user).count() >= 3:
                raise ValueError("Maximum 3 family contacts allowed per user")
        
        super().save(*args, **kwargs)


class CommunityMembership(models.Model):
    """
    Model for tracking user participation in communities.
    """
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='community_memberships',
        help_text="User who is a member of the community"
    )
    community_id = models.CharField(
        max_length=100,
        help_text="Unique identifier for the community"
    )
    community_name = models.CharField(
        max_length=200,
        help_text="Name of the community"
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'users_community_membership'
        verbose_name = 'Community Membership'
        verbose_name_plural = 'Community Memberships'
        unique_together = ['user', 'community_id']
    
    def __str__(self):
        return f"{self.user.name} - {self.community_name}"


class SOSEvent(models.Model):
    """
    Model for tracking SOS events triggered by users.
    """
    
    STATUS_CHOICES = [
        ('triggered', 'Triggered'),
        ('sms_sent', 'SMS Sent'),
        ('police_called', 'Police Called'),
        ('geofence_alerted', 'Geofence Alerted'),
        ('resolved', 'Resolved'),
    ]
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sos_events',
        help_text="User who triggered the SOS"
    )
    # Use JSONField instead of PointField for location
    location = models.JSONField(
        null=True,
        blank=True,
        help_text="Location where SOS was triggered (longitude, latitude)"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='triggered',
        help_text="Current status of the SOS event"
    )
    triggered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(
        blank=True,
        help_text="Additional notes about the SOS event"
    )
    
    class Meta:
        db_table = 'users_sos_event'
        verbose_name = 'SOS Event'
        verbose_name_plural = 'SOS Events'
        ordering = ['-triggered_at']
    
    def __str__(self):
        return f"SOS Event - {self.user.name} at {self.triggered_at}"
