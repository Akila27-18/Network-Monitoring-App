from django.shortcuts import render, redirect
from django.db.models import Sum
from django.http import HttpResponse
import csv
import io
from django.utils import timezone

from authsystem.decorators import role_required
from .models import NetworkLog, Alert
from threatintel.models import ThreatIP
from django.http import JsonResponse



def dashboard_data_api(request):
    logs = NetworkLog.objects.order_by('-timestamp')[:12]
    timeline_labels = [log.timestamp.strftime("%H:%M:%S") for log in logs[::-1]]
    timeline_data = [log.bytes_transferred for log in logs[::-1]]

    top_ips = (
        NetworkLog.objects.values('source_ip')
        .annotate(total=Sum('bytes_transferred'))
        .order_by('-total')[:5]
    )
    top_ip_labels = [r['source_ip'] for r in top_ips]
    top_ip_values = [r['total'] for r in top_ips]

    return JsonResponse({
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
        "top_ip_labels": top_ip_labels,
        "top_ip_values": top_ip_values,
    })

def stats_partial(request):
    total_logs = NetworkLog.objects.count()
    active_alerts = Alert.objects.filter(severity="High").count()
    unique_ips = NetworkLog.objects.values("source_ip").distinct().count()
    threat_count = ThreatIP.objects.count()

    return render(request, "monitor/partials/stats_partial.html", {
        "total_logs": total_logs,
        "active_alerts": active_alerts,
        "unique_ips": unique_ips,
        "threat_count": threat_count,
    })



# Dashboard (existing)
@role_required(['admin', 'analyst', 'viewer'])
def dashboard_view(request):
    total_logs = NetworkLog.objects.count()
    active_alerts = Alert.objects.filter(severity="High").count()
    unique_ips = NetworkLog.objects.values("source_ip").distinct().count()
    threat_count = ThreatIP.objects.count()

    # timeline (last 12 entries)
    logs = NetworkLog.objects.order_by('-timestamp')[:12]
    timeline_labels = [log.timestamp.strftime("%H:%M:%S") for log in logs[::-1]]  # oldest -> newest
    timeline_data = [log.bytes_transferred for log in logs[::-1]]

    top_ips = (
        NetworkLog.objects.values('source_ip')
        .annotate(total=Sum('bytes_transferred'))
        .order_by('-total')[:5]
    )
    top_ip_labels = [r['source_ip'] for r in top_ips]
    top_ip_values = [r['total'] for r in top_ips]

    latest_alerts = Alert.objects.order_by('-timestamp')[:5]

    return render(request, "monitor/dashboard.html", {
        "total_logs": total_logs,
        "active_alerts": active_alerts,
        "unique_ips": unique_ips,
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
        "top_ip_labels": top_ip_labels,
       "top_ip_values": top_ip_values,
        "latest_alerts": latest_alerts,
        "threat_count": threat_count,
    })




# --- Alerts list ---
@role_required(['admin', 'analyst', 'viewer'])
def alerts_list_view(request):
    alerts = Alert.objects.order_by('-timestamp')
    return render(request, "monitor/alerts.html", {"alerts": alerts})


# HTMX partial endpoint for alert refresh
@role_required(['admin', 'analyst', 'viewer'])
def alerts_partial(request):
    latest_alerts = Alert.objects.order_by('-timestamp')[:10]
    return render(request, "monitor/alerts_partial.html", {
        "latest_alerts": latest_alerts
    })



# --- Anomalies (just queries of recent detections) ---
@role_required(['admin', 'analyst', 'viewer'])
def anomalies_view(request):
    # For now, anomalies are Alerts with severity "High" or special flag
    anomalies = Alert.objects.filter(severity="High").order_by('-timestamp')
    return render(request, "monitor/anomalies.html", {"anomalies": anomalies})


# --- System Status ---
@role_required(['admin', 'analyst', 'viewer'])
def system_status_view(request):
    # Provide some basic info. You can extend with real sniffer status.
    total_logs = NetworkLog.objects.count()
    last_log = NetworkLog.objects.order_by('-timestamp').first()
    last_time = last_log.timestamp if last_log else None

    context = {
        "total_logs": total_logs,
        "last_log_time": last_time,
        "npcap_running": True,   # you can replace with real check
        "sniffer_interface": request.GET.get("iface", "auto-detected"),
    }
    return render(request, "monitor/system_status.html", context)
def logs_partial(request):
    logs = NetworkLog.objects.order_by('-timestamp')[:50]  # latest 50
    return render(request, "monitor/partials/logs_partial.html", {"logs": logs})

@role_required(['admin', 'analyst', 'viewer'])
def traffic_view(request):
    logs = NetworkLog.objects.order_by('-timestamp')[:300]  # correct model

    # HTMX request = return only the table
    if request.htmx:
        return render(request, "monitor/partials/traffic_table.html", {"logs": logs})

    # Regular page view = return full page
    return render(request, "monitor/traffic.html", {"logs": logs})



# --- Reports & Exports ---
@role_required(['admin', 'analyst', 'viewer'])
def reports_view(request):
    # options page: daily summary etc.
    total_logs = NetworkLog.objects.count()
    return render(request, "monitor/reports.html", {"total_logs": total_logs})


@role_required(['admin', 'analyst', 'viewer'])
def export_logs_csv(request):
    # Export recent logs as CSV
    logs = NetworkLog.objects.order_by('-timestamp')[:1000]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "source_ip", "destination_ip", "protocol", "bytes_transferred"])
    for l in logs:
        writer.writerow([l.timestamp.isoformat(), l.source_ip, l.destination_ip, l.protocol, l.bytes_transferred])
    resp = HttpResponse(buf.getvalue(), content_type="text/csv")
    resp['Content-Disposition'] = 'attachment; filename=network_logs.csv'
    return resp
