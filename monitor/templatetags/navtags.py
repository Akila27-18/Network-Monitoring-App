from django import template
from django.urls import reverse

register = template.Library()

@register.inclusion_tag("monitor/navlink.html")
def navlink(url_name, icon, label, current_path):
    resolved_url = reverse(url_name)
    return {
        "url_name": url_name,
        "icon": icon,
        "label": label,
        "current_path": current_path,
        "resolved_url": resolved_url,
    }
