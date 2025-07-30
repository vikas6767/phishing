from django.urls import path
from .views import *
from . import views

urlpatterns = [
    path('', Home.as_view(), name = 'home'),
    path('api/', Prediction.as_view(), name = 'prediction'),
    path('analyze_email/', views.analyze_email, name='analyze_email'),
]