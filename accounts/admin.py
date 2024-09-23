from django.contrib import admin
from .models import User, OneTimePassword

class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', "last_name")
class OneTimePasswordAdmin(admin.ModelAdmin):
    list_display = ("user", "code")

# Register your models here.
admin.site.register(OneTimePassword, OneTimePasswordAdmin)
admin.site.register(User, UserAdmin)