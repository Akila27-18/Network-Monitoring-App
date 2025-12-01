from django.urls import path
from . import views

app_name = "monitor"

urlpatterns = [
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("traffic/", views.traffic_view, name="traffic"),

    path("alerts/", views.alerts_list_view, name="alerts"),
    path("stats/partial/", views.stats_partial, name="stats_partial"),
    path("dashboard/api/data/", views.dashboard_data_api, name="dashboard_data_api"),
   
    path("logs/partial/", views.logs_partial, name="logs_partial"),

    path("alerts/partial/", views.alerts_partial, name="alerts_partial"),
    path("anomalies/", views.anomalies_view, name="anomalies"),
    path("system/", views.system_status_view, name="system"),
    path("reports/", views.reports_view, name="reports"),
    path("reports/export/csv/", views.export_logs_csv, name="export_logs_csv"),
]

