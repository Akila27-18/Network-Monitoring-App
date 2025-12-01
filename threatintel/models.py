from django.db import models

class ThreatIP(models.Model):
    ip = models.CharField(max_length=64, unique=True)
    source = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip} ({self.source})"
