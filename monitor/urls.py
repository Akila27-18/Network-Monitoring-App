from django.urls import path
from .views import dashboard_view, alerts_view, logs_view

urlpatterns = [
    path("dashboard/", dashboard_view, name="dashboard"),
    path('alerts/', alerts_view, name='alerts'),
    path('logs/', logs_view, name='logs'),
]
