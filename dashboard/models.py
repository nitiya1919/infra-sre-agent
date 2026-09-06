from django.db import models
from django.contrib.auth.models import User

class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100)  # e.g., "TRIGGER_AWX", "RETRY_JOB", "EXPORT_POST_MORTEM", "LOGIN"
    resource = models.CharField(max_length=255) # e.g., "Incident #3 (AWX Template #1)"
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        username = self.user.username if self.user else "Anonymous/System"
        return f"[{self.timestamp}] {username} - {self.action} on {self.resource}"

class IncidentAlert(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=[('HIGH', 'High'), ('MEDIUM', 'Medium'), ('LOW', 'Low')], default='MEDIUM')
    status = models.CharField(max_length=30, default='PENDING', choices=[('PENDING', 'Pending Review'), ('APPROVED', 'Executing'), ('RUNNING', 'Running'), ('RESOLVED', 'Resolved'), ('FAILED', 'Failed')])
    awx_template_id = models.IntegerField(default=1)
    ai_analysis = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class AutomationAuditLog(models.Model):
    incident = models.ForeignKey(IncidentAlert, on_delete=models.CASCADE)
    awx_job_id = models.CharField(max_length=100)
    status = models.CharField(max_length=50)
    executed_at = models.DateTimeField(auto_now_add=True)
