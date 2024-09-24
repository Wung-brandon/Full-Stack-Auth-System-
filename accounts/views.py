from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response 
from .serializers import UserRegisterSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from .utils import send_code_to_user_email
from .models import User, OneTimePassword


# Create your views here.
class UserRegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]
    
    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            print("user data", user)
            # send email function to user['email']
            # first_name = user.get('first_name', 'User')
            send_code_to_user_email(user['email'])
            return Response({
                'data' : user,
                'message' : f"Hi {user['first_name']} thanks for signing up with us. A passcode has been sent to your email address"
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyUserEmailOTPView(GenericAPIView):
    def post(self, request, *args, **kwargs):
        # otpCode = self.kwargs.get('otp')
        otpCode = request.data.get('otp')
        try:
            user_code_obj = OneTimePassword.objects.get(code=otpCode)
            user = user_code_obj.user
            if not user.is_verified:
                user.is_verified = True
                return Response({
                    "message": "Account email is verified successfully"
                }, status=status.HTTP_200_OK)
            return Response({
                "message" : "Code is invalid. account is verified already."
            }, status=status.HTTP_204_NO_CONTENT)
            
        except OneTimePassword.DoesNotExist:
            return Response({
                "message" : "Passcode not provided"
            }, status=status.HTTP_404_NOT_FOUND)