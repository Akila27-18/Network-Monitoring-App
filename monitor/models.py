from django.db import models

class NetworkLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=50)
    destination_ip = models.CharField(max_length=50)
    protocol = models.CharField(max_length=20)
    bytes_transferred = models.IntegerField()


    def __str__(self):
        return f"{self.source_ip} -> {self.destination_ip}"


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.CharField(max_length=200)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="Low")
    reviewed = models.BooleanField(default=False)

    def __str__(self):
        return f"[{self.severity}] {self.message}"
