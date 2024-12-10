import os, shutil, sys
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

from utilities.common import isValidPhone


def validate_phone(value):
    if not isValidPhone(value): 
        raise ValidationError(
            "%(value)s is not valid phone number",
            params={"value": value},
        )

class User(AbstractUser):
    phone = models.PositiveBigIntegerField(validators=[validate_phone], null = True, blank=True)
    phone_verified = models.BooleanField(default=False)
    image = models.ImageField(upload_to='media/', null=True, blank=True)
    image_url = models.URLField(null=True, blank = True)
    bio = models.TextField(default='', null = True, blank = True)
    deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    pass


class LoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uuid = models.CharField(max_length=255, null=True)
    fcm_token = models.TextField(default='')
    os = models.CharField(max_length=255, null=True)
    os_version = models.CharField(max_length=255, null=True)
    app_version = models.CharField(max_length=255, null=True)
    device = models.CharField(max_length=255, null=True)
    device_model = models.CharField(max_length=255, null=True)
    social_provider = models.CharField(max_length=255, null=True)
    is_dashbaord_login = models.BooleanField(default=False, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


class ForgotPassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=10, null=False)
    phone = models.PositiveBigIntegerField(validators=[validate_phone], null = True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


@receiver(post_save, sender=User)
def user_post_save(sender, instance, created, **kwargs):
    # prevent calling save twice
    if hasattr(instance, '_dirty'):
        return

    if instance.image:
        try:
            dst = '{0}/userphoto/{1}'.format(str(settings.MEDIA_ROOT), instance.id)
            src = '{0}/media'.format(str(settings.MEDIA_ROOT))
            filename = '/' + str(instance.image).split('/')[-1]
            os.makedirs(dst, exist_ok=True)
            shutil.move(src + filename, dst + filename)
            instance.image = str(instance.image).replace('media', 'userphoto/{0}'.format(instance.id))
            instance.image_url = settings.APP_URL + instance.image.url
            # instance.image = None
            instance._dirty = True
            instance.save()
        except FileNotFoundError:
            print("Wrong file or file path")
        finally:
            try: 
                del instance._dirty
            except: 
                pass