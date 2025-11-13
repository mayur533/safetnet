from rest_framework import serializers
from .models import SOSAlert, Case, Incident, OfficerProfile, Notification  # new models for security_app


class SOSAlertSerializer(serializers.ModelSerializer):
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    geofence_name = serializers.CharField(source='geofence.name', read_only=True)
    assigned_officer_name = serializers.CharField(source='assigned_officer.name', read_only=True)

    class Meta:
        model = SOSAlert
        fields = (
            'id', 'user', 'user_username', 'user_email', 'geofence', 'geofence_name',
            'location_lat', 'location_long', 'status', 'priority', 'assigned_officer', 'assigned_officer_name',
            'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'user', 'user_username', 'user_email', 'created_at', 'updated_at')


class SOSAlertCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SOSAlert
        fields = ('geofence', 'location_lat', 'location_long', 'priority')

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class CaseSerializer(serializers.ModelSerializer):
    sos_user_username = serializers.CharField(source='sos_alert.user.username', read_only=True)
    officer_name = serializers.CharField(source='officer.name', read_only=True)
    sos_alert_status = serializers.CharField(source='sos_alert.status', read_only=True)

    class Meta:
        model = Case
        fields = (
            'id', 'sos_alert', 'sos_user_username', 'officer', 'officer_name',
            'description', 'status', 'sos_alert_status', 'updated_at'
        )
        read_only_fields = ('id', 'updated_at')


class CaseCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Case
        fields = ('sos_alert', 'description')

    def create(self, validated_data):
        # Auto-assign the current officer
        try:
            from users.models import SecurityOfficer
            officer = SecurityOfficer.objects.get(email=self.context['request'].user.email)
            validated_data['officer'] = officer
        except SecurityOfficer.DoesNotExist:
            pass
        return super().create(validated_data)


class CaseUpdateStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Case
        fields = ('status', 'description')

    def validate_status(self, value):
        if value not in dict(Case.STATUS_CHOICES):
            raise serializers.ValidationError('Invalid status value.')
        return value


class IncidentSerializer(serializers.ModelSerializer):
    officer_name = serializers.CharField(source='officer.name', read_only=True)
    sos_status = serializers.CharField(source='sos_alert.status', read_only=True)

    class Meta:
        model = Incident
        fields = (
            'id', 'officer', 'officer_name', 'sos_alert', 'case', 'description',
            'location_lat', 'location_long', 'status', 'sos_status', 'timestamp'
        )
        read_only_fields = ('id', 'timestamp')


class OfficerProfileSerializer(serializers.ModelSerializer):
    officer_name = serializers.CharField(source='officer.name', read_only=True)
    officer_phone = serializers.CharField(source='officer.contact', read_only=True)
    officer_geofence = serializers.CharField(source='officer.assigned_geofence.name', read_only=True)

    class Meta:
        model = OfficerProfile
        fields = ('officer', 'officer_name', 'officer_phone', 'officer_geofence', 'on_duty', 'updated_at')
        read_only_fields = ('officer', 'officer_name', 'officer_phone', 'officer_geofence', 'updated_at')


class NotificationSerializer(serializers.ModelSerializer):
    officer_name = serializers.CharField(source='officer.name', read_only=True)
    sos_alert_id = serializers.IntegerField(source='sos_alert.id', read_only=True)
    case_id = serializers.IntegerField(source='case.id', read_only=True)

    class Meta:
        model = Notification
        fields = (
            'id', 'officer', 'officer_name', 'title', 'message', 'notification_type',
            'is_read', 'sos_alert', 'sos_alert_id', 'case', 'case_id',
            'created_at', 'read_at'
        )
        read_only_fields = ('id', 'officer', 'created_at', 'read_at')


class NotificationAcknowledgeSerializer(serializers.Serializer):
    notification_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of notification IDs to mark as read"
    )

