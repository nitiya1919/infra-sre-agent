import time
import os
from dotenv import load_dotenv
load_dotenv('/home/ubuntu/infra-sre-agent/creds.env')
from celery import shared_task
import requests
from django.conf import settings
from .models import AutomationAuditLog, IncidentAlert
from .sre_agent import run_sre_agent_diagnosis 
from .sanitizer import sanitize_log_payload  # 1. Added import

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
    raw_host = getattr(settings, 'AWX_HOST', None) or os.getenv('AWX_HOST', 'http://23.20.167.26:30080')
    host = str(raw_host).rstrip('/')
    if 'localhost' in host or not host:
        host = 'http://23.20.167.26:30080'
    if host.endswith('/api/v2'):
        host = host[:-7]

    username = getattr(settings, 'AWX_USERNAME', os.getenv('AWX_USERNAME', 'admin'))
    password = getattr(settings, 'AWX_PASSWORD', os.getenv('AWX_PASSWORD', ''))

    # 2. PRE-FLIGHT REACHABILITY CHECK (Target specific AWX API endpoint)
    print(f"[*] Pre-flight check: Verifying reachability of AWX controller at {host}...")
    try:
        response = requests.get(f"{host}/api/v2/ping/", auth=(username, password), verify=False, timeout=5)
        if response.status_code != 200:
            raise requests.ConnectionError(f"AWX Endpoint returned HTTP {response.status_code}")
    except Exception as conn_err:
        incident.status = 'FAILED'
        incident.save()
        
        raw_error = f"CRITICAL: AWX Controller at {host} is unreachable or invalid. Error: {str(conn_err)}"
        # Sanitize sensitive data (IPs, URLs) before sending to Agent or Database
        sanitized_error = sanitize_log_payload(raw_error)
        
        print(f"[!] {sanitized_error} -> Handing off to Strands Agent for RCA...")
        
        ai_diagnosis = "RCA generation skipped or timed out."
        try:
            ai_diagnosis = run_sre_agent_diagnosis(incident_data, sanitized_error)
        except Exception as agent_err:
            ai_diagnosis = f"Agent diagnosis failed: {str(agent_err)}"

        AutomationAuditLog.objects.create(
            incident=incident, 
            awx_job_id="DEAD-CONTROLLER", 
            status=f"REACHABILITY_FAIL | {sanitized_error} | 🤖 Strands RCA: {ai_diagnosis}"
        )
        return f"AWX Controller unreachable. Strands Agent RCA completed."

    # 3. Launch AWX Job
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
            job_id = job_data.get('job') or job_data.get('id')
            
            # Require a legitimate integer AWX Job ID
            if not job_id or not str(job_id).isdigit():
                incident.status = 'FAILED'
                incident.save()
                
                err_msg = "HTTP 200/201 received but target host did not return a valid AWX Job ID."
                sanitized_err_msg = sanitize_log_payload(err_msg)
                
                ai_suggestion = run_sre_agent_diagnosis(incident_data, sanitized_err_msg)
                
                AutomationAuditLog.objects.create(
                    incident=incident,
                    awx_job_id="INVALID-RESP",
                    status=f"FAIL | {sanitized_err_msg} | 🤖 Strands RCA: {ai_suggestion}"
                )
                return "Invalid AWX response."

            # 4. POLL AWX JOB STATUS UNTIL FINISHED
            job_url = f"{host}/api/v2/jobs/{job_id}/"
            job_status = "running"
            
            for _ in range(30):  # Poll up to 60 seconds (30 * 2s)
                time.sleep(2)
                poll_resp = requests.get(job_url, headers=headers, timeout=5)
                if poll_resp.status_code == 200:
                    job_status = poll_resp.json().get('status', 'running')
                    if job_status in ['successful', 'failed', 'error', 'canceled']:
                        break

            if job_status == 'successful':
                incident.status = 'RESOLVED'
                incident.save()
                AutomationAuditLog.objects.create(
                    incident=incident, 
                    awx_job_id=str(job_id), 
                    status=f"SUCCESS | Launched AWX Job #{job_id} and execution completed successfully."
                )
                return f"AWX Job {job_id} succeeded."
            else:
                incident.status = 'FAILED'
                incident.save()
                
                base_error = f"AWX Job #{job_id} executed but ended with status: '{job_status}'"
                sanitized_error = sanitize_log_payload(base_error)
                
                ai_suggestion = "RCA generation skipped."
                try:
                    ai_suggestion = run_sre_agent_diagnosis(incident_data, sanitized_error)
                except Exception:
                    pass

                AutomationAuditLog.objects.create(
                    incident=incident, 
                    awx_job_id=str(job_id), 
                    status=f"EXECUTION_FAILED | {sanitized_error} | 🤖 Strands RCA: {ai_suggestion}"
                )
                return f"AWX Job {job_id} failed."

        else:
            incident.status = 'FAILED'
            incident.save()
            clean_error = response.text[:150].replace('\n', ' ').replace('\r', '')
            base_error = f"HTTP {response.status_code} | Target URL: {url} | Response: {clean_error}"
            sanitized_error = sanitize_log_payload(base_error)
            
            ai_suggestion = "RCA generation skipped."
            try:
                ai_suggestion = run_sre_agent_diagnosis(incident_data, sanitized_error)
            except Exception:
                pass

            AutomationAuditLog.objects.create(
                incident=incident, 
                awx_job_id="FAIL-API", 
                status=f"{sanitized_error} | 🤖 Strands RCA: {ai_suggestion}"
            )
            return f"AWX returned status {response.status_code}"

    except Exception as e:
        incident.status = 'FAILED'
        incident.save()
        base_error = f"ERR | Target URL: {url} | Exception: {str(e)[:150]}"
        sanitized_error = sanitize_log_payload(base_error)
        
        ai_suggestion = "RCA generation skipped."
        try:
            ai_suggestion = run_sre_agent_diagnosis(incident_data, sanitized_error)
        except Exception:
            pass

        AutomationAuditLog.objects.create(
            incident=incident, 
            awx_job_id="ERR-500", 
            status=f"{sanitized_error} | 🤖 Strands RCA: {ai_suggestion}"
        )
        return f"Error connecting to AWX: {str(e)}"
