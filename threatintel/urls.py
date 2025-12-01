from django.urls import path
from . import views

app_name = "threatintel"

urlpatterns = [
    path("", views.threats_list, name="list"),
    path("add/", views.threats_add, name="add"),
    path("delete/<int:pk>/", views.threats_delete, name="delete"),
]
