from django.db import models

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
