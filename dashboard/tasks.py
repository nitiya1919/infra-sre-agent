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
    
    incident_data = {
        "id": incident.id,
        "title": getattr(incident, 'title', 'Unknown Alert'),
        "severity": getattr(incident, 'severity', 'UNKNOWN'),
        "template_id": template_id
    }

    # 1. Normalize AWX Base Host safely
    raw_host = getattr(settings, 'AWX_HOST', None) or 'http://localhost'
    host = str(raw_host).rstrip('/')
    if host.endswith('/api/v2'):
        host = host[:-7]

    # 2. PRE-FLIGHT REACHABILITY CHECK (Strict 3-second timeout)
    print(f"[*] Pre-flight check: Verifying reachability of AWX controller at {host}...")
    try:
        response = requests.get(f"{host}/api/v2/", timeout=3)
    except (requests.ConnectionError, requests.Timeout, Exception) as conn_err:
        incident.status = 'FAILED'
        incident.save()
        
        raw_error = f"CRITICAL: AWX Automation Controller at {host} is unreachable or terminated. Error: {str(conn_err)}"
        print(f"[!] {raw_error} -> Handing off to Strands Agent for RCA...")
        
        # Safely invoke Strands Agent with protection against hanging LLM calls
        ai_diagnosis = "RCA generation skipped or timed out."
        try:
            ai_diagnosis = run_sre_agent_diagnosis(incident_data, raw_error)
        except Exception as agent_err:
            ai_diagnosis = f"Agent diagnosis failed: {str(agent_err)}"

        log_detail = f"REACHABILITY_FAIL | 🤖 Strands RCA: {ai_diagnosis}"
        
        AutomationAuditLog.objects.create(
            incident=incident, 
            awx_job_id="DEAD-CONTROLLER", 
            status=log_detail
        )
        return f"AWX Controller unreachable. Strands Agent RCA completed."

    # 3. Proceed to Launch if Reachable
    url = f"{host}/api/v2/job_templates/{template_id}/launch/"
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
            
            ai_suggestion = "RCA generation skipped."
            try:
                ai_suggestion = run_sre_agent_diagnosis(incident_data, base_error)
            except Exception:
                pass

            log_detail = f"{base_error} | 🤖 Strands RCA: {ai_suggestion}"
            
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
        
        ai_suggestion = "RCA generation skipped."
        try:
            ai_suggestion = run_sre_agent_diagnosis(incident_data, base_error)
        except Exception:
            pass

        log_detail = f"{base_error} | 🤖 Strands RCA: {ai_suggestion}"
        
        AutomationAuditLog.objects.create(
            incident=incident, 
            awx_job_id="ERR-500", 
            status=log_detail
        )
        return f"Error connecting to AWX: {str(e)}"
