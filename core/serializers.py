from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import User, DonorProfile, BloodBank, DonationRequest, DonationHistory

# Use get_user_model for consistency, but we've defined custom User model
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'role', 'first_name', 'last_name']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2', 'first_name', 'last_name', 'role']

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords didn't match."})
        
        # Check if username already exists
        if User.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError({"username": "A user with that username already exists."})
        
        # Check if email already exists
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({"email": "A user with that email already exists."})
            
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        
        user = User(
            email=validated_data['email'],
            username=validated_data['username'],
            role=validated_data.get('role', 'donor'),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        user.set_password(password)
        user.save()
        
        # If donor, create empty DonorProfile
        if user.role == 'donor':
            DonorProfile.objects.create(user=user, blood_group='O+')
            
        return user

class DonorProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = DonorProfile
        fields = ['id', 'user', 'phone', 'blood_group', 'city', 'last_donation', 'profile_photo']

class BloodBankSerializer(serializers.ModelSerializer):
    class Meta:
        model = BloodBank
        fields = '__all__'

class DonationRequestSerializer(serializers.ModelSerializer):
    donor = UserSerializer(read_only=True)
    
    class Meta:
        model = DonationRequest
        fields = '__all__'
        read_only_fields = ['status', 'created_at', 'processed_by']

class DonationHistorySerializer(serializers.ModelSerializer):
    donor = UserSerializer(read_only=True)
    
    class Meta:
        model = DonationHistory
        fields = '__all__'