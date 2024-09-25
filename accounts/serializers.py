from lib2to3.pgen2.tokenize import TokenError
from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, smart_bytes, force_str
from django.shortcuts import redirect
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken
class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    class Meta:
        model =User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']
    
    def validate(self, attrs):
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')
        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        # or method 2
        # if attrs['password'] != attrs['password2']:
        #     raise serializers.ValidationError("Passwords do must match.")
        return attrs
    

    def create(self, validated_data):
        user = User.objects.create_user(
            email = validated_data['email'],
            first_name = validated_data['first_name'],
            last_name = validated_data['last_name'],
            password = validated_data['password']
        )
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    password = serializers.CharField(max_length=255, min_length=6, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "full_name", "access_token", "refresh_token"]

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')

        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("Credentials not valid. Try again")

        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")

        try:
            user_tokens = user.tokens()  # Ensure tokens method is working
            access_token = user_tokens.get('access')
            refresh_token = user_tokens.get('refresh')
            print("Access token: ", user_tokens.get('access'))
            print("Refresh token: ", user_tokens.get('refresh'))
        except Exception as e:
            raise AuthenticationFailed("Token generation failed: " + str(e))

        return {
            'email': user.email,
            'full_name': user.get_full_name,
            'access_token': str(access_token),
            'refresh_token': str(refresh_token),
        }

class PasswordResetRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=6)
    
    class Meta:
        model = User
        fields = ["email"]
    
    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.filter(email=email).first()
        
        if user:
            # Create an instance of PasswordResetTokenGenerator
            token_generator = PasswordResetTokenGenerator()
            
            uidb64 = urlsafe_base64_encode(smart_bytes(user.pk))
            # Use the token generator instance to generate a token
            token = token_generator.make_token(user)
            
            request = self.context.get("request")
            site_domain = get_current_site(request).domain
            relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absolute_link = f"http://{site_domain}{relative_link}"
            
            email_body = f"Hi, use the link below to reset your password. \n {absolute_link}"
            data = {
                "email_body": email_body,
                "email_subject": "Reset Your Password",
                "to_email": user.email,
            }
            send_normal_email(data)
        
        # return super().validate(attrs)
            
        
    
class SetNewPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ["password", "confirm_password", "uidb64", "token"]
    def validate(self, attrs):
        try:
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")
            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("Reset Link is Invalid or has expired", 401)
            if password != confirm_password:
                raise AuthenticationFailed("Password do not match")
            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            raise AuthenticationFailed(f"Link is expired or Invalid. The error is {e}")
        
class LogoutUserSerializer(serializers.ModelSerializer):
    refresh_token = serializers.CharField()
    
    default_error_messages = {
        "bad token" : "Token is invalid or has expired"
    }
    def validate(self, attrs):
        self.token = attrs.get("refresh_token") 
        return attrs
    
    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            self.fail("bad token")
        