"""
Middleware to update authenticated user's location from request headers.

Frontend can send headers on any request:
  - X-User-Lat: latitude (float)
  - X-User-Lng: longitude (float)

When both are present and valid, the user's location is updated.
"""

from typing import Optional

from django.utils.deprecation import MiddlewareMixin


class HeaderLocationMiddleware(MiddlewareMixin):
    """Extracts X-User-Lat/X-User-Lng and updates user location if authenticated."""

    def process_request(self, request):
        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            return None

        lat_header = request.headers.get('X-User-Lat') or request.META.get('HTTP_X_USER_LAT')
        lng_header = request.headers.get('X-User-Lng') or request.META.get('HTTP_X_USER_LNG')

        if lat_header is None or lng_header is None:
            return None

        try:
            latitude = float(lat_header)
            longitude = float(lng_header)
        except (TypeError, ValueError):
            return None

        # Basic coordinate bounds validation
        if not (-90.0 <= latitude <= 90.0) or not (-180.0 <= longitude <= 180.0):
            return None

        try:
            # users.models.User implements set_location(longitude, latitude)
            user.set_location(longitude, latitude)
        except Exception:
            # Never block the request due to location update issues
            return None

        return None


