"""
API views for User models.
"""
import logging
from django.conf import settings
from django.http import Http404
# from django.contrib.gis.geos import Point  # Commented out to avoid GDAL dependency
# from django.contrib.gis.measure import Distance  # Commented out to avoid GDAL dependency
# from django.contrib.gis.db.models.functions import Distance as DistanceFunction  # Commented out to avoid GDAL dependency
from django.utils import timezone
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import User, FamilyContact, CommunityMembership, SOSEvent
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    FamilyContactSerializer, FamilyContactCreateSerializer,
    CommunityMembershipSerializer, CommunityMembershipCreateSerializer,
    SOSEventSerializer, SOSTriggerSerializer, UserLocationUpdateSerializer
)
from .services import SMSService, GeofenceService

logger = logging.getLogger(__name__)


class UserRegistrationView(APIView):
    """
    User registration endpoint.
    POST /users/
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Register a new user."""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            logger.info(f"New user registered: {user.email}")
            
            return Response({
                'message': 'User registered successfully',
                'user': UserProfileSerializer(user).data,
                'tokens': {
                    'access': str(access_token),
                    'refresh': str(refresh)
                }
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(TokenObtainPairView):
    """
    User login endpoint with JWT authentication.
    POST /users/login/
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        """Login user and return JWT tokens."""
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            logger.info(f"User logged in: {user.email}")
            
            return Response({
                'message': 'Login successful',
                'user': UserProfileSerializer(user).data,
                'tokens': {
                    'access': str(access_token),
                    'refresh': str(refresh)
                }
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Get and update user profile.
    GET /users/<id>/
    PUT/PATCH /users/<id>/
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        """Get the user's profile by ID or current user."""
        user_id = self.kwargs.get('user_id')
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                # Allow users to access their own profile
                if self.request.user.id == user.id:
                    return user
                else:
                    # For now, allow access to any profile (you can restrict this later)
                    return user
            except User.DoesNotExist:
                raise Http404("User not found")
        else:
            # For /profile/ endpoint, return current user
            return self.request.user
    
    def get(self, request, *args, **kwargs):
        """Get user profile."""
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response(serializer.data)
    
    def put(self, request, *args, **kwargs):
        """Update user profile."""
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"User profile updated: {user.email}")
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request, *args, **kwargs):
        """Partially update user profile."""
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"User profile updated: {user.email}")
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLocationUpdateView(APIView):
    """
    Update user location.
    POST /users/<id>/location/
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, user_id):
        """Update user's current location."""
        if request.user.id != int(user_id):
            return Response(
                {'error': 'You can only update your own location.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = UserLocationUpdateSerializer(data=request.data)
        if serializer.is_valid():
            longitude = serializer.validated_data['longitude']
            latitude = serializer.validated_data['latitude']
            
            request.user.set_location(longitude, latitude)
            logger.info(f"User location updated: {request.user.email}")
            
            return Response({
                'message': 'Location updated successfully',
                'location': request.user.get_location_dict()
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FamilyContactListView(generics.ListCreateAPIView):
    """
    List and create family contacts.
    GET /users/<id>/family_contacts/
    POST /users/<id>/family_contacts/
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get family contacts for the current user."""
        return FamilyContact.objects.filter(user=self.request.user)
    
    def get_serializer_class(self):
        """Return appropriate serializer based on request method."""
        if self.request.method == 'POST':
            return FamilyContactCreateSerializer
        return FamilyContactSerializer
    
    def perform_create(self, serializer):
        """Create a new family contact."""
        serializer.save(user=self.request.user)
        logger.info(f"Family contact created for user: {self.request.user.email}")
    
    def list(self, request, *args, **kwargs):
        """List family contacts."""
        queryset = self.get_queryset()
        serializer = FamilyContactSerializer(queryset, many=True)
        return Response(serializer.data)


class FamilyContactDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a family contact.
    GET /users/<id>/family_contacts/<contact_id>/
    PUT/PATCH /users/<id>/family_contacts/<contact_id>/
    DELETE /users/<id>/family_contacts/<contact_id>/
    """
    serializer_class = FamilyContactSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get family contacts for the current user."""
        return FamilyContact.objects.filter(user=self.request.user)
    
    def destroy(self, request, *args, **kwargs):
        """Delete a family contact."""
        instance = self.get_object()
        self.perform_destroy(instance)
        logger.info(f"Family contact deleted for user: {request.user.email}")
        return Response(status=status.HTTP_204_NO_CONTENT)


class CommunityMembershipListView(generics.ListAPIView):
    """
    List user's community memberships.
    GET /users/<id>/communities/
    """
    serializer_class = CommunityMembershipSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get community memberships for the current user."""
        return CommunityMembership.objects.filter(
            user=self.request.user,
            is_active=True
        )


class CommunityJoinView(APIView):
    """
    Join a community.
    POST /users/<id>/communities/
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, user_id):
        """Join a community."""
        if request.user.id != int(user_id):
            return Response(
                {'error': 'You can only join communities for your own account.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = CommunityMembershipCreateSerializer(data=request.data)
        if serializer.is_valid():
            community_id = serializer.validated_data['community_id']
            community_name = serializer.validated_data['community_name']
            
            membership = CommunityMembership.objects.create(
                user=request.user,
                community_id=community_id,
                community_name=community_name
            )
            
            logger.info(f"User joined community: {request.user.email} - {community_name}")
            
            return Response({
                'message': 'Successfully joined community',
                'membership': CommunityMembershipSerializer(membership).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CommunityLeaveView(APIView):
    """
    Leave a community.
    DELETE /users/<id>/communities/<community_id>/
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request, user_id, community_id):
        """Leave a community."""
        if request.user.id != int(user_id):
            return Response(
                {'error': 'You can only leave communities for your own account.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            membership = CommunityMembership.objects.get(
                user=request.user,
                community_id=community_id
            )
            membership.is_active = False
            membership.save()
            
            logger.info(f"User left community: {request.user.email} - {community_id}")
            
            return Response({
                'message': 'Successfully left community'
            }, status=status.HTTP_200_OK)
        
        except CommunityMembership.DoesNotExist:
            return Response(
                {'error': 'Community membership not found.'},
                status=status.HTTP_404_NOT_FOUND
            )


class SOSTriggerView(APIView):
    """
    Trigger SOS event.
    POST /users/<id>/sos/
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, user_id):
        """Trigger SOS event."""
        if request.user.id != int(user_id):
            return Response(
                {'error': 'You can only trigger SOS for your own account.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = SOSTriggerSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            longitude = serializer.validated_data.get('longitude')
            latitude = serializer.validated_data.get('latitude')
            notes = serializer.validated_data.get('notes', '')
            
            # Create SOS event
            sos_event = SOSEvent.objects.create(
                user=user,
                notes=notes
            )
            
            # Set location if provided
            if longitude is not None and latitude is not None:
                sos_event.location = Point(longitude, latitude)
                sos_event.save()
            
            # Send SMS to family contacts
            sms_service = SMSService()
            family_contacts = FamilyContact.objects.filter(user=user)
            
            for contact in family_contacts:
                try:
                    sms_service.send_sos_alert(
                        to_phone=contact.phone,
                        user_name=user.name,
                        user_phone=user.phone,
                        location=sos_event.location
                    )
                    logger.info(f"SOS SMS sent to family contact: {contact.phone}")
                except Exception as e:
                    logger.error(f"Failed to send SOS SMS to {contact.phone}: {str(e)}")
            
            # Check geofence and send alerts if needed
            geofence_service = GeofenceService()
            if sos_event.location:
                try:
                    geofence_service.check_and_alert_geofence(
                        user=user,
                        location=sos_event.location,
                        sos_event=sos_event
                    )
                    logger.info(f"Geofence check completed for user: {user.email}")
                except Exception as e:
                    logger.error(f"Geofence check failed for user {user.email}: {str(e)}")
            
            # Update SOS event status
            sos_event.status = 'sms_sent'
            sos_event.save()
            
            #logger.info(f"SOS event triggered for user: {user.email}")
            logger.info(f"SOS event triggered for user: {user.email}")
            
            return Response({
                'message': 'SOS event triggered successfully',
                'sos_event': SOSEventSerializer(sos_event).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SOSEventListView(generics.ListAPIView):
    """
    List user's SOS events.
    GET /users/<id>/sos_events/
    """
    serializer_class = SOSEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get SOS events for the current user."""
        return SOSEvent.objects.filter(user=self.request.user)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_stats(request, user_id):
    """
    Get user statistics.
    GET /users/<id>/stats/
    """
    if request.user.id != int(user_id):
        return Response(
            {'error': 'You can only view your own statistics.'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    user = request.user
    
    stats = {
        'total_family_contacts': FamilyContact.objects.filter(user=user).count(),
        'active_community_memberships': CommunityMembership.objects.filter(
            user=user, is_active=True
        ).count(),
        'total_sos_events': SOSEvent.objects.filter(user=user).count(),
        'is_premium': user.is_premium,
        'plan_type': user.plantype,
        'plan_expiry': user.planexpiry,
    }
    
    return Response(stats)
