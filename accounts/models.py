from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.validators import validate_email


class UserManager(BaseUserManager):
    def email_validator(self, email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValidationError(_("please enter a valid email address"))
        
    def create_user(self, email, first_name, last_name, password, **extra_fields):
        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError("Email is required")
        if not first_name:
            raise ValueError("First name is required")
        if not last_name:
            raise ValueError("Last name is required")
        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            **extra_fields
            )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, first_name, last_name, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)
        extra_fields.setdefault("is_active", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("is staff must be true for the admin user")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("is superuser must be true for the admin user")
        user = self.create_user(email, first_name, last_name, password, **extra_fields)
        user.save(using=self._db)
        return user
# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=200, unique=True, verbose_name=_('Email Address'))
    first_name = models.CharField(max_length=150, verbose_name=_('First Name'))
    last_name = models.CharField(max_length=150, verbose_name=_('Last Name'))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    objects = UserManager()
    
    def __str__(self):
        return self.email
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def token(self):
        pass

class OneTimePassword(models.Model):
    user = models.OneToOneField(User, related_name="user_code", on_delete=models.CASCADE)
    code = models.CharField(max_length=6, unique=True)
    
    def __str__(self):
        return f"{self.user.first_name} - passcode {self.code}"