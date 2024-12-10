from __future__ import unicode_literals
from django.db import IntegrityError


# import sentry_sdk
from rest_framework import status
from rest_framework.views import Response, exception_handler
from rest_framework.exceptions import APIException


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first to get the standard error response.
    response = exception_handler(exc, context)

    # if there is an IntegrityError and the error response hasn't already been generated
    # if isinstance(exc, IntegrityError) and not response:
    #     response = Response(
    #         {
    #             'message': 'IntegrityError'
    #         },
    #         status=status.HTTP_400_BAD_REQUEST
    #     )
    #     sentry_sdk.capture_exception(exc)

    return response


class ServiceUnavailable(APIException):
    status_code = 503
    default_detail = 'Service temporarily unavailable, try again later.'
    default_code = 'service_unavailable'