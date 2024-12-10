from django.urls import path
from .views import *

urlpatterns = [
    path('', UserListCreateView.as_view()),
    path('me/', UserRetrieveView.as_view()),

    path('<int:pk>/',UserRUDView.as_view()),
    path('<int:pk>/login/', UserLoginListCreateView.as_view()),
    path('password/reset/link/',PasswordResetLink.as_view()),
    path('password/reset/confirm/', PasswordResetConfirm.as_view()),


   
]