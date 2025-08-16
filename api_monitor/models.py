import uuid

from django.db import models
from django.contrib.auth.models import User

class ClientFingerprint(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    token = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField()
    host = models.CharField(max_length=255, blank=True)
    user_agent = models.TextField(blank=True)
    country = models.CharField(max_length=100, blank=True)
    session_id = models.CharField(max_length=255, blank=True)
    cookie_data = models.JSONField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        db_table = "client_fingerprint"
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['token']),
            models.Index(fields=['ip_address']),
        ]
    def __str__(self):
        return f"{self.user} {self.ip_address} - {self.token}"

ALERT_SEVERITY = (
    ('info', 'Info'),
    ('warning', 'Warning'),
    ('critical', 'Critical'),
)

class APIAccessLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_method = models.CharField(max_length=10)
    url_path = models.TextField()
    view_name = models.CharField(max_length=255, blank=True)
    execution_time = models.FloatField()
    duration_bucket = models.CharField(max_length=20, blank=True)
    memory_usage = models.FloatField(null=True, blank=True)
    cpu_percent = models.FloatField(null=True, blank=True)
    status_code = models.IntegerField()
    query_count = models.IntegerField()
    is_error = models.BooleanField(default=False)
    error_type = models.CharField(max_length=255, blank=True)
    error_description = models.TextField(blank=True)
    client_fingerprint = models.ForeignKey(ClientFingerprint, null=True, blank=True, on_delete=models.SET_NULL, related_name='api_access_log_client_fingerprint')
    is_suspicious = models.BooleanField(default=False)
    suspicious_reason = models.TextField(blank=True)
    is_sql_injection_suspected = models.BooleanField(default=False)
    sql_injection_pattern = models.CharField(max_length=255, blank=True)
    # is_rate_limited = models.BooleanField(default=False)
    # rate_limited_reason = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=20, choices=ALERT_SEVERITY, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        db_table = "api_access_log"
        indexes = [
            models.Index(fields=['url_path']),
            models.Index(fields=['status_code']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"{self.request_method} {self.url_path} - {self.status_code}"

USER_DESIGNATIONS = (
    ('owner', 'Owner'),
    ('admin', 'Admin'),
    ('developer', 'Developer'),
    ('analyst', 'Analyst'),
    ('support', 'Support'),
    ('other', 'Other'),
)

class AlertRecipient(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    designation = models.CharField(max_length=255, blank=True, choices=USER_DESIGNATIONS)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='alert_recipient_created_by')
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='alert_recipient_updated_by')

    class Meta:
        ordering = ['-created_at']
        db_table = "alert_recipient"

    def __str__(self):
        return f"{self.email} {self.designation}"