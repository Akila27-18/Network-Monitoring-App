from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('verify/<uidb64>/<token>/', views.email_verify_view, name='email_verify'),

    # Activity log page
    path('activity/logs/', views.activity_logs_view, name='activity_logs'),
]
