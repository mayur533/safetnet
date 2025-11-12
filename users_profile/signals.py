"""
Signal handlers for User models.
"""
import logging
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import User, FamilyContact, SOSEvent

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
def user_post_save(sender, instance, created, **kwargs):
    """
    Handle user creation and updates.
    """
    if created:
        logger.info(f"New user created: {instance.email}")
    else:
        logger.info(f"User updated: {instance.email}")


@receiver(pre_save, sender=FamilyContact)
def family_contact_pre_save(sender, instance, **kwargs):
    """
    Handle family contact creation and updates.
    """
    if not instance.pk:  # New contact being created
        # Ensure maximum 3 contacts per user
        existing_count = FamilyContact.objects.filter(user=instance.user).count()
        if existing_count >= 3:
            raise ValueError("Maximum 3 family contacts allowed per user")
        
        logger.info(f"New family contact being created for user: {instance.user.email}")
    else:
        logger.info(f"Family contact being updated for user: {instance.user.email}")


@receiver(post_save, sender=SOSEvent)
def sos_event_post_save(sender, instance, created, **kwargs):
    """
    Handle SOS event creation and updates.
    """
    if created:
        logger.info(f"SOS event created for user: {instance.user.email}")
        
        # Trigger emergency response
        from .services import EmergencyService
        emergency_service = EmergencyService()
        emergency_service.trigger_emergency_response(instance.user, instance)
    else:
        logger.info(f"SOS event updated for user: {instance.user.email}")
