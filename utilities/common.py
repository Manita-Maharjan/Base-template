# import math, requests, re, jwt
import re
from django.conf import settings
from django.core.exceptions import ValidationError



# def calculate_wilson_score(rating): 
#     p = (rating['1'] * 0.0) + (rating['2'] * 0.25) + (rating['3'] * 0.5) + (rating['4'] * 0.75) + (rating['5'] * 1.0)
#     n = (rating['5'] * 0.0) + (rating['4'] * 0.25) + (rating['3'] * 0.5) + (rating['2'] * 0.75) + (rating['1'] * 1.0)
#     wilson_score = ((p + 1.9208) / (p + n) - 1.96 * math.sqrt((p * n) / (p + n) + 0.9604) / (p + n)) / (1 + 3.8416 / (p + n)) if  p + n > 0  else 0
#     return wilson_score


# def convertToDecimal(value):
#     if value: 
#         r = re.compile("[0-9]*[.,]?[0-9]*\Z")
#         if r.match(value):
#             return value
#     return None


def isValidPhone(value): 
    if value: 
        # r = re.compile("[9][6-9]\d{8}")
        r = re.compile(r"[9][6-9]\d{8}")
        # r = re.compile('@"^\(?([0-9]{3})\)?[-.●]?([0-9]{3})[-.●]?([0-9]{4})$')
        if r.match(str(value)):
            return value
    return None





# def sendSms(to, text): 
#     payload = {
#             "token": settings.SPARROW_SMS_TOKEN,
#             "from": "FOODIEHO",
#             "to": to,
#             "text":text
#         }


#     if settings.APP_ENVIRONMENT == 'prod' or settings.SMS_DEBUG: 
#         from sms.models import SmsBalance
#         response = requests.post(settings.SPARROW_SMS_URL, json = payload)
#         json_response = response.json()
#         if response.status_code == 200:
#             sms_balance = SmsBalance.objects.all().first()
#             sms_balance.credit_available = json_response['credit_available']
#             sms_balance.save()
#             return True
        
#         return False
    
#     return True


# def getStaff(request):
#     if hasattr(request, "auth"):
#         token =  jwt.decode(request.auth.token, options={"verify_signature": False})
#         if 'is_dashboard_login' in token: 
#             return request.user
        
#     return None


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip