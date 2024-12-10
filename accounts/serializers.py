from .models import *

from rest_framework import serializers, exceptions, status
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


from utilities.permission import has_dashboard_access
from utilities.error_handler import CustomValidation


from datetime import timedelta,datetime

import random



class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    username = serializers.CharField()
    email = serializers.EmailField()
    is_active = serializers.BooleanField(default = True)

    class Meta:
        model = User
        fields = ['id','username','password','email','phone', 'phone_verified','image','image_url','bio', 'first_name', 'last_name', 'is_active', 'created_at','deleted','deleted_at']
        read_only_fields = ['id', 'created_at','updated_at']

    def validate_username(self, value):
        """
        Check that the username is unique case insensitive
        """
        if User.objects.filter(username__iexact=value).count():
            raise CustomValidation('Username already exist.','username', status_code=status.HTTP_409_CONFLICT)
        return value

    def validate_email(self, value):
        """
        Check that the email is unique case insensitive
        """
        if User.objects.filter(email__iexact=value).count():
            raise CustomValidation('Email already exist.','email', status_code=status.HTTP_409_CONFLICT)
        return value
    
    def validate_phone(self, value):
        """
        Check that the email is unique case insensitive
        """
        if User.objects.filter(phone= value).exists():
            raise CustomValidation('This phone number already exist.','phone', status_code=status.HTTP_409_CONFLICT)
        return value
    

    def create(self, validated_data):
        user = super().create(validated_data)
        user.set_password(validated_data['password'])
        user.save()

        return user
    
    def update(self, instance, validated_data):
        if 'phone' in validated_data and not instance.phone == validated_data.get('phone'):
            instance.phone_verified = False
    
        return super().update(instance, validated_data)
    

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['phone'] = instance.phone if not instance.phone or (instance.phone and (self.context['request'].user == instance or  self.context['request'].user.is_superuser)) else str(instance.phone).replace(str(instance.phone)[4:8], "****")
        return data
    
    
    
class UserBriefSerializer(serializers.ModelSerializer):
    class Meta: 
        model = User 
        fields = ['id', 'first_name','last_name','username','email','phone','phone_verified','image_url']


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta: 
        model = LoginHistory
        fields = "__all__"


#custom jwt-authentication passing user info too 
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    
    def validate(self, attrs):       # it validates all the fields present in the model
        data = super().validate(attrs)

        login_data = self.context['request'].data['device_info'] if 'device_info' in  self.context['request'].data else {}
        login_data['user'] = self.user.id
        login_serializer = LoginHistorySerializer(data=login_data)
        if login_serializer.is_valid():
            login_serializer.save()

        refresh = self.get_token(self.user)

        serializer = UserBriefSerializer(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        data['user'] = serializer.data

        return data
 

class ForgotPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = ForgotPassword
        fields = '__all__'
        read_only_fields = ['user', 'code', 'updated_at', 'created_at']
   
    def validate_phone(self, value):
        if not isValidPhone(value):
            raise serializers.ValidationError("phone number is not valid")

        user  = User.objects.filter(phone__iexact = str(value)).first()

        five_minute_ago = datetime.now() - timedelta(minutes=5)
        one_month_ago = datetime.now() - timedelta(days=30)
        forgot_password = ForgotPassword.objects.filter(user = user)
        if forgot_password.filter(created_at__gte = one_month_ago).count() > 3:
            raise CustomValidation('User validating phone limit reached','message',status_code=status.HTTP_200_OK)

        if forgot_password.filter(created_at__gte = five_minute_ago).count():
            raise CustomValidation('Forget password code has been already sent','message', status_code=status.HTTP_200_OK)
        
        return value