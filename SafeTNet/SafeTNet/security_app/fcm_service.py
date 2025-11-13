import requests
import json
from django.conf import settings
from django.utils import timezone


class FCMService:
    """Firebase Cloud Messaging service for sending push notifications"""
    
    def __init__(self):
        self.server_key = getattr(settings, 'FCM_SERVER_KEY', None)
        self.fcm_url = 'https://fcm.googleapis.com/fcm/send'
    
    def send_notification(self, registration_tokens, title, body, data=None):
        """
        Send push notification to FCM tokens
        
        Args:
            registration_tokens (list): List of FCM registration tokens
            title (str): Notification title
            body (str): Notification body
            data (dict): Additional data payload
        """
        if not self.server_key:
            print("FCM_SERVER_KEY not configured. Skipping push notification.")
            return False
        
        if not registration_tokens:
            print("No registration tokens provided.")
            return False
        
        headers = {
            'Authorization': f'key={self.server_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'registration_ids': registration_tokens,
            'notification': {
                'title': title,
                'body': body,
                'sound': 'default',
                'badge': 1
            },
            'data': data or {},
            'priority': 'high'
        }
        
        try:
            response = requests.post(
                self.fcm_url,
                headers=headers,
                data=json.dumps(payload),
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            if result.get('success', 0) > 0:
                print(f"FCM notification sent successfully to {result.get('success')} devices")
                return True
            else:
                print(f"FCM notification failed: {result}")
                return False
                
        except requests.RequestException as e:
            print(f"FCM request failed: {str(e)}")
            return False
        except Exception as e:
            print(f"FCM error: {str(e)}")
            return False
    
    def send_to_officer(self, officer, title, body, data=None):
        """
        Send notification to a specific officer
        """
        # In a real implementation, you'd get FCM tokens from officer's device
        # For now, we'll use a placeholder
        registration_tokens = getattr(officer, 'fcm_tokens', [])
        if not registration_tokens:
            # Fallback: try to get from a related model or user profile
            try:
                if hasattr(officer, 'user') and hasattr(officer.user, 'fcm_tokens'):
                    registration_tokens = officer.user.fcm_tokens
            except:
                pass
        
        return self.send_notification(registration_tokens, title, body, data)


# Global FCM service instance
fcm_service = FCMService()
