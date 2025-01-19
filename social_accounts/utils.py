from google.auth.transport import requests
from google.oauth2 import id_token
from accounts.models import User
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed


class Google():
    
    @staticmethod
    def validate(access_token):
        try:
            id_info = id_token.verify_oauth2_token(access_token, requests.Request())
            
            if id_info['iss'] in ['accounts.google.com', 'https://accounts.google.com']:
                return id_info
            else:
                raise ValueError('Invalid issuer.')    
            # if id_info['aud']!= settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY:
            #     raise ValueError('Invalid audience.')
            # if id_info['sub'] is None:
            #     raise ValueError('No user ID.')
            # user = User.objects.get(social_id=id_info['sub'])
            # if user.is_anonymous:
            #     user = authenticate(social_id=id_info['sub'])
            # return user
        except Exception as e:
            raise AuthenticationFailed('Unable to authenticate with Google.') from e 
def login_social_user(email, password):
    user = authenticate(email=email, password=password)
    user_tokens = user.tokens()
    return {
        'email': user.email,
        'full_name': user.get_full_name,
        'access_token': str(user_tokens.get("access")),
        'refresh_token': str(user_tokens.get("refresh")),
    }
            
def register_social_user(provider, email, first_name, last_name):
    user = User.objects.filter(email=email)
    if user.exists():
        if provider == user[0].auth_provider:
            login_social_user(email, settings.SOCIAL_AUTH_PASSWORD)
        else:
            raise AuthenticationFailed(
                detail=f"please continue your login with {user[0].auth_provider}"
            )
    else:
        new_user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=settings.SOCIAL_AUTH_PASSWORD,
            auth_provider=provider
        )
        new_user.is_verified = True
        new_user.save()
        login_social_user(email=new_user.email password=settings.SOCIAL_AUTH_PASSWORD)     
    
    