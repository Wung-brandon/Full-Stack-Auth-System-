from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response 
from .serializers import UserRegisterSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from .utils import send_code_to_user_email


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
            # send email function to user['email']
            send_code_to_user_email(user['email'])
            return Response({
                'data' : user,
                'message' : f"Hi {user.first_name} thanks for signing up with us. A passcode has been sent to your email address"
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)