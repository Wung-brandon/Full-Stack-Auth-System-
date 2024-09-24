from django.urls import path
from .views import UserRegisterView, VerifyUserEmailOTPView


urlpatterns = [
    path("register/", UserRegisterView.as_view(), name="register"),
    path("verify-email/", VerifyUserEmailOTPView.as_view(), name="verify-email"),
]
