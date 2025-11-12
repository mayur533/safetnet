"""
Serializers for User models.
"""
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, FamilyContact, CommunityMembership, SOSEvent


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    """
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('name', 'email', 'phone', 'password', 'password_confirm', 'plantype')
        extra_kwargs = {
            'plantype': {'default': 'free'}
        }
    
    def validate(self, attrs):
        """Validate that passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs
    
    def create(self, validated_data):
        """Create a new user."""
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        """Validate user credentials."""
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(email=email, password=password)
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include email and password.')


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile (read and update).
    """
    location = serializers.SerializerMethodField()
    is_premium = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = (
            'id', 'name', 'email', 'phone', 'plantype', 
            'planexpiry', 'location', 'is_premium', 
            'date_joined', 'last_login'
        )
        read_only_fields = ('id', 'email', 'date_joined', 'last_login')
    
    def get_location(self, obj):
        """Get location as a dictionary."""
        return obj.get_location_dict()
    
    def update(self, instance, validated_data):
        """Update user profile."""
        # Handle location update if provided
        location_data = self.initial_data.get('location')
        if location_data:
            try:
                longitude = float(location_data.get('longitude'))
                latitude = float(location_data.get('latitude'))
                instance.set_location(longitude, latitude)
            except (ValueError, TypeError):
                raise serializers.ValidationError('Invalid location data.')
        
        return super().update(instance, validated_data)


class FamilyContactSerializer(serializers.ModelSerializer):
    """
    Serializer for family contacts.
    """
    
    class Meta:
        model = FamilyContact
        fields = ('id', 'name', 'phone', 'relationship', 'is_primary', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def validate(self, attrs):
        """Validate family contact data."""
        user = self.context['request'].user
        
        # Check if phone number already exists for this user
        phone = attrs.get('phone')
        if phone:
            existing_contact = FamilyContact.objects.filter(
                user=user, 
                phone=phone
            ).exclude(id=self.instance.id if self.instance else None)
            
            if existing_contact.exists():
                raise serializers.ValidationError(
                    {'phone': 'A contact with this phone number already exists.'}
                )
        
        return attrs


class FamilyContactCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating family contacts.
    """
    
    class Meta:
        model = FamilyContact
        fields = ('name', 'phone', 'relationship', 'is_primary')
    
    def validate(self, attrs):
        """Validate family contact creation."""
        user = self.context['request'].user
        
        # Check maximum contacts limit
        if FamilyContact.objects.filter(user=user).count() >= 3:
            raise serializers.ValidationError(
                'Maximum 3 family contacts allowed per user.'
            )
        
        # Check if phone number already exists
        phone = attrs.get('phone')
        if FamilyContact.objects.filter(user=user, phone=phone).exists():
            raise serializers.ValidationError(
                {'phone': 'A contact with this phone number already exists.'}
            )
        
        return attrs


class CommunityMembershipSerializer(serializers.ModelSerializer):
    """
    Serializer for community memberships.
    """
    
    class Meta:
        model = CommunityMembership
        fields = ('id', 'community_id', 'community_name', 'joined_at', 'is_active')
        read_only_fields = ('id', 'joined_at')


class CommunityMembershipCreateSerializer(serializers.Serializer):
    """
    Serializer for joining communities.
    """
    community_id = serializers.CharField(max_length=100)
    community_name = serializers.CharField(max_length=200)
    
    def validate(self, attrs):
        """Validate community membership."""
        user = self.context['request'].user
        community_id = attrs.get('community_id')
        
        # Check if user is already a member
        if CommunityMembership.objects.filter(
            user=user, 
            community_id=community_id
        ).exists():
            raise serializers.ValidationError(
                'You are already a member of this community.'
            )
        
        return attrs


class SOSEventSerializer(serializers.ModelSerializer):
    """
    Serializer for SOS events.
    """
    location = serializers.SerializerMethodField()
    
    class Meta:
        model = SOSEvent
        fields = (
            'id', 'location', 'status', 'triggered_at', 
            'resolved_at', 'notes'
        )
        read_only_fields = ('id', 'triggered_at', 'resolved_at')
    
    def get_location(self, obj):
        """Get location as a dictionary."""
        if obj.location:
            return {
                'longitude': obj.location.x,
                'latitude': obj.location.y
            }
        return None


class SOSTriggerSerializer(serializers.Serializer):
    """
    Serializer for triggering SOS events.
    """
    longitude = serializers.FloatField(required=False)
    latitude = serializers.FloatField(required=False)
    notes = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        """Validate SOS trigger data."""
        longitude = attrs.get('longitude')
        latitude = attrs.get('latitude')
        
        # If location is provided, both coordinates must be present
        if longitude is not None and latitude is None:
            raise serializers.ValidationError(
                'Both longitude and latitude must be provided for location.'
            )
        if latitude is not None and longitude is None:
            raise serializers.ValidationError(
                'Both longitude and latitude must be provided for location.'
            )
        
        return attrs


class UserLocationUpdateSerializer(serializers.Serializer):
    """
    Serializer for updating user location.
    """
    longitude = serializers.FloatField()
    latitude = serializers.FloatField()
    
    def validate(self, attrs):
        """Validate location coordinates."""
        longitude = attrs.get('longitude')
        latitude = attrs.get('latitude')
        
        # Basic coordinate validation
        if not (-180 <= longitude <= 180):
            raise serializers.ValidationError(
                {'longitude': 'Longitude must be between -180 and 180.'}
            )
        
        if not (-90 <= latitude <= 90):
            raise serializers.ValidationError(
                {'latitude': 'Latitude must be between -90 and 90.'}
            )
        
        return attrs
