from celery import shared_task
import requests
from django.conf import settings
from .models import AutomationAuditLog, IncidentAlert
from .sre_agent import run_sre_agent_diagnosis  

@shared_task
def trigger_awx_job(incident_id, template_id):
    try:
        incident = IncidentAlert.objects.get(id=incident_id)
    except IncidentAlert.DoesNotExist:
        return f"Incident {incident_id} not found."

    incident.status = 'RUNNING'
    incident.save()
    
    # Prepare incident context to give the Agent situational awareness
    incident_data = {
        "id": incident.id,
        "title": getattr(incident, 'title', 'Unknown Alert'),
        "severity": getattr(incident, 'severity', 'UNKNOWN'),
        "template_id": template_id
    }

    # 1. Normalize AWX Base Host
    host = settings.AWX_HOST.rstrip('/')
    if host.endswith('/api/v2'):
        host = host[:-7]

    url = f"{host}/api/v2/job_templates/{template_id}/launch/"

    # 2. Sanitize Token
    token = str(getattr(settings, 'AWX_TOKEN', '')).strip().strip("'").strip('"')

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(
            url, 
            headers=headers, 
            json={'extra_vars': {'incident_id': incident_id}}, 
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            job_data = response.json()
            job_id = str(job_data.get('job', job_data.get('id', 'simulated_101')))
            
            incident.status = 'RESOLVED'
            incident.save()
            AutomationAuditLog.objects.create(
                incident=incident, 
                awx_job_id=job_id, 
                status=f"SUCCESS | Launched AWX Job #{job_id}"
            )
            return f"AWX Job {job_id} launched successfully."
        else:
            incident.status = 'FAILED'
            incident.save()
            clean_error = response.text[:150].replace('\n', ' ').replace('\r', '')
            base_error = f"HTTP {response.status_code} | Target URL: {url} | Response: {clean_error}"
            
            # ---> Trigger Strands Agent SDK Analysis on API failure <---
            ai_suggestion = run_sre_agent_diagnosis(incident_data, base_error)
            log_detail = f"{base_error} | 🤖 Agentic AI: {ai_suggestion}"
            
            AutomationAuditLog.objects.create(
                incident=incident, 
                awx_job_id="FAIL-API", 
                status=log_detail
            )
            return f"AWX returned status {response.status_code}"

    except Exception as e:
        incident.status = 'FAILED'
        incident.save()
        base_error = f"ERR | Target URL: {url} | Exception: {str(e)[:150]}"
        
        # ---> Trigger Strands Agent SDK Analysis on exceptions <---
        ai_suggestion = run_sre_agent_diagnosis(incident_data, base_error)
        log_detail = f"{base_error} | 🤖 Agentic AI: {ai_suggestion}"
        
        AutomationAuditLog.objects.create(
            incident=incident, 
            awx_job_id="ERR-500", 
            status=log_detail
        )
        return f"Error connecting to AWX: {str(e)}"
