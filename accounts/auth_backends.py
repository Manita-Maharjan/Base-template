from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q


class UsernameOrPhoneBackend(ModelBackend):
    def authenticate(self, request, **kwargs):
        UserModel = get_user_model()
        try:
            username = kwargs.get('username', None)
            if not username.isdigit():
                user = UserModel.objects.get(username__iexact=username)
            else: 
                user = UserModel.objects.get(phone=int(username))
            if user.check_password(kwargs.get('password', None)):
                return user
        except UserModel.DoesNotExist:
            return None
        return None