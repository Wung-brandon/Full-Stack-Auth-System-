from django.urls import path
from .views import UserRegisterView, VerifyUserEmailOTPView, LoginUserView, TestAuthenticationView, PasswordResetConfirmView, PasswordResetRequestView, SetNewPasswordView, LogoutUserView


urlpatterns = [
    path("register/", UserRegisterView.as_view(), name="register"),
    path("verify-email/", VerifyUserEmailOTPView.as_view(), name="verify-email"),
    path("login/", LoginUserView.as_view(), name="login"),
    path("granted/", TestAuthenticationView.as_view(), name="granted"),
    
    path("password-reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password-reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("set-new-password/", SetNewPasswordView.as_view(), name="set-new-password"),
    path("logout/", LogoutUserView.as_view(), name="logout"),
]
