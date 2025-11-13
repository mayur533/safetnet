"""
Simplified services for SMS functionality (without geospatial dependencies).
Use this file if you're having trouble with GDAL installation.
"""
import logging
from django.conf import settings
import requests
import json

logger = logging.getLogger(__name__)


class SMSService:
    """
    Service for sending SMS messages via Twilio and Exotel.
    """
    
    def __init__(self):
        self.twilio_client = None
        self.exotel_sid = settings.EXOTEL_SID
        self.exotel_token = settings.EXOTEL_TOKEN
        self.exotel_app_id = settings.EXOTEL_APP_ID
        
        # Initialize Twilio client if credentials are available
        if settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN:
            try:
                from twilio.rest import Client as TwilioClient
                self.twilio_client = TwilioClient(
                    settings.TWILIO_ACCOUNT_SID,
                    settings.TWILIO_AUTH_TOKEN
                )
            except Exception as e:
                logger.error(f"Failed to initialize Twilio client: {str(e)}")
    
    def send_sos_alert(self, to_phone, user_name, user_phone, location=None):
        """
        Send SOS alert SMS to family contact.
        """
        message = self._format_sos_message(user_name, user_phone, location)
        
        # Try Twilio first, then Exotel
        if self.twilio_client:
            return self._send_via_twilio(to_phone, message)
        elif self.exotel_sid and self.exotel_token:
            return self._send_via_exotel(to_phone, message)
        else:
            logger.error("No SMS service configured")
            raise Exception("SMS service not configured")
    
    def _format_sos_message(self, user_name, user_phone, location=None):
        """Format SOS alert message."""
        message = f"🚨 SOS ALERT 🚨\n\n{user_name} has triggered an emergency alert!\n"
        message += f"Contact: {user_phone}\n"
        
        if location:
            if isinstance(location, dict):
                lat = location.get('latitude')
                lng = location.get('longitude')
            else:
                # Handle case where location might be a different format
                lat = getattr(location, 'y', None) if hasattr(location, 'y') else None
                lng = getattr(location, 'x', None) if hasattr(location, 'x') else None
            
            if lat is not None and lng is not None:
                message += f"Location: {lat:.6f}, {lng:.6f}\n"
                message += f"Google Maps: https://maps.google.com/?q={lat},{lng}\n"
        
        message += "\nPlease contact them immediately and call emergency services if needed."
        return message
    
    def _send_via_twilio(self, to_phone, message):
        """Send SMS via Twilio."""
        try:
            message_obj = self.twilio_client.messages.create(
                body=message,
                from_=settings.TWILIO_PHONE_NUMBER,
                to=to_phone
            )
            logger.info(f"SMS sent via Twilio to {to_phone}: {message_obj.sid}")
            return True
        except Exception as e:
            logger.error(f"Twilio SMS failed to {to_phone}: {str(e)}")
            raise
    
    def _send_via_exotel(self, to_phone, message):
        """Send SMS via Exotel."""
        try:
            url = f"https://api.exotel.com/v1/Accounts/{self.exotel_sid}/Sms/send.json"
            
            data = {
                'From': settings.TWILIO_PHONE_NUMBER,  # Use configured phone number
                'To': to_phone,
                'Body': message
            }
            
            response = requests.post(
                url,
                data=data,
                auth=(self.exotel_sid, self.exotel_token),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if response.status_code == 200:
                logger.info(f"SMS sent via Exotel to {to_phone}")
                return True
            else:
                logger.error(f"Exotel SMS failed to {to_phone}: {response.text}")
                raise Exception(f"Exotel API error: {response.text}")
                
        except Exception as e:
            logger.error(f"Exotel SMS failed to {to_phone}: {str(e)}")
            raise


class GeofenceService:
    """
    Simplified geofencing service without geospatial dependencies.
    """
    
    def __init__(self):
        self.radius_meters = getattr(settings, 'GEOFENCE_RADIUS_METERS', 100)
    
    def check_and_alert_geofence(self, user, location, sos_event):
        """
        Check if user is within authorized geofence zones and send alerts.
        """
        # This is a simplified implementation
        # In a real application, you would have a GeofenceZone model
        # and check against authorized zones for the user
        
        # For now, we'll just log the geofence check
        logger.info(f"Geofence check for user {user.email} at location {location}")
        
        # Update SOS event status
        sos_event.status = 'geofence_alerted'
        sos_event.save()
        
        # In a real implementation, you would:
        # 1. Query GeofenceZone model for user's authorized zones
        # 2. Check if current location is within any authorized zone
        # 3. Send alerts to community members if within authorized zone
        # 4. Send alerts to security officers if outside authorized zone
        
        return True
    
    def is_within_geofence(self, location, geofence_center, radius_meters=None):
        """
        Check if a location is within a geofence using simple distance calculation.
        """
        if radius_meters is None:
            radius_meters = self.radius_meters
        
        # Simple distance calculation (not as accurate as proper geospatial)
        if isinstance(location, dict) and isinstance(geofence_center, dict):
            lat1, lng1 = location.get('latitude', 0), location.get('longitude', 0)
            lat2, lng2 = geofence_center.get('latitude', 0), geofence_center.get('longitude', 0)
            
            # Simple distance calculation (approximate)
            import math
            distance = math.sqrt((lat2 - lat1)**2 + (lng2 - lng1)**2) * 111000  # Rough conversion to meters
            return distance <= radius_meters
        
        return False
    
    def get_nearby_geofences(self, location, radius_meters=None):
        """
        Get geofences within a certain radius of a location.
        """
        if radius_meters is None:
            radius_meters = self.radius_meters
        
        # This would query a GeofenceZone model in a real implementation
        # For now, return empty list
        return []


class EmergencyService:
    """
    Service for emergency response coordination.
    """
    
    def __init__(self):
        self.sms_service = SMSService()
    
    def trigger_emergency_response(self, user, sos_event):
        """
        Coordinate emergency response for SOS event.
        """
        try:
            # Send SMS to family contacts
            family_contacts = user.family_contacts.all()
            for contact in family_contacts:
                try:
                    self.sms_service.send_sos_alert(
                        to_phone=contact.phone,
                        user_name=user.name,
                        user_phone=user.phone,
                        location=sos_event.location
                    )
                except Exception as e:
                    logger.error(f"Failed to send emergency SMS to {contact.phone}: {str(e)}")
            
            # In a real implementation, you would also:
            # 1. Call emergency services API
            # 2. Send alerts to nearby community members
            # 3. Notify security officers
            # 4. Log the emergency event
            
            logger.info(f"Emergency response triggered for user: {user.email}")
            return True
            
        except Exception as e:
            logger.error(f"Emergency response failed for user {user.email}: {str(e)}")
            return False
