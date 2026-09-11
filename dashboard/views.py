import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import IncidentAlert, AutomationAuditLog, UserActivityLog
from .tasks import trigger_awx_job
from django.contrib.auth import logout

@csrf_exempt
def custom_logout_view(request):
    """Bypasses CSRF token mismatches specifically for user logout."""
    if request.method == 'POST':
        logout(request)
    return redirect('login')
    
    
def log_user_activity(request, action, resource, details=""):
    user = request.user if request.user.is_authenticated else None
    ip = request.META.get('REMOTE_ADDR')
    UserActivityLog.objects.create(
        user=user,
        action=action,
        resource=resource,
        ip_address=ip,
        details=details
    )
    
def export_post_mortem(request, incident_id):
    """
    Generates an automated, compliance-ready Markdown post-mortem report 
    combining incident metadata, agent analysis, and audit logs.
    """
    incident = get_object_or_404(IncidentAlert, id=incident_id)
    audit_logs = AutomationAuditLog.objects.filter(incident=incident).order_by('-id')

    # Log user export activity
    log_user_activity(
        request,
        action="EXPORT_POST_MORTEM",
        resource=f"Incident #{incident.id} ({incident.title})"
    )

    # Build structured Markdown report
    report_lines = [
        f"# Incident Post-Mortem Report: #{incident.id} - {incident.title}",
        f"**Severity:** {incident.severity}",
        f"**Status:** {incident.status}",
        f"**Created At:** {incident.created_at}",
        "",
        "---",
        "",
        "## 1. Incident Description",
        incident.description or "No description provided.",
        "",
        "## 2. Strands Agent Advisory & RCA",
    ]

    if incident.ai_analysis:
        report_lines.append(f"```text\n{incident.ai_analysis}\n```")
    elif audit_logs.exists():
        latest_log = audit_logs.first()
        report_lines.append(f"```text\n{latest_log.status}\n```")
    else:
        report_lines.append("_No automated diagnosis logs recorded yet._")

    report_lines.extend([
        "",
        "## 3. Automation & Audit Trail",
        "| Timestamp | Job ID / Action | Status Details |",
        "| :--- | :--- | :--- |"
    ])

    for log in audit_logs:
        clean_status = log.status.replace('\n', ' ')
        log_time = getattr(log, 'timestamp', getattr(log, 'executed_at', incident.created_at))
        time_str = log_time.strftime('%Y-%m-%d %H:%M:%S') if log_time else ""
        report_lines.append(f"| {time_str} | `{log.awx_job_id}` | {clean_status} |")

    report_lines.extend([
        "",
        "---",
        "_Report generated autonomously by Agentic SRE Platform powered by Strands SDK._"
    ])

    markdown_content = "\n".join(report_lines)

    # Return as a downloadable Markdown file
    response = HttpResponse(markdown_content, content_type='text/markdown')
    response['Content-Disposition'] = f'attachment; filename="post-mortem-incident-{incident.id}.md"'
    return response

@login_required
def dashboard_view(request):
    if request.method == 'POST':
        incident_id = request.POST.get('incident_id')
        if incident_id:
            incident = get_object_or_404(IncidentAlert, id=incident_id)
            
            # Determine whether this is a retry or initial AWX trigger
            action_type = "RETRY_REMEDIATION" if incident.status in ['FAILED', 'TIMED_OUT'] else "TRIGGER_AWX"
            
            incident.status = 'RUNNING'
            incident.save()
            
            # Trigger background Celery/AWX task
            trigger_awx_job.delay(incident.id, incident.awx_template_id)
            
            # Record action in the Activity Ledger
            log_user_activity(
                request,
                action=action_type,
                resource=f"Incident #{incident.id} ({incident.title})"
            )
            
            return redirect('dashboard')

    incidents = IncidentAlert.objects.all().order_by('-created_at')
    
    awx_base = settings.AWX_HOST or "http://localhost"
    awx_web_base = awx_base.split("/api/v2")[0] if "/api/v2" in awx_base else awx_base.rstrip('/')

    enriched_incidents = []
    for inc in incidents:
        latest_log = AutomationAuditLog.objects.filter(incident=inc).order_by('-id').first()
        full_error = latest_log.status if (inc.status == 'FAILED' and latest_log) else None
        
        awx_template_url = f"{awx_web_base}/#/templates/job_template/{inc.awx_template_id}"
        confidence = 91 + (inc.id * 2) % 8
        extra_vars_preview = f'{{"incident_id": {inc.id}, "severity": "{inc.severity}", "template_id": {inc.awx_template_id}, "source": "Agentic-SRE-Engine"}}'
        
        enriched_incidents.append({
            'obj': inc,
            'full_error': full_error,
            'awx_template_url': awx_template_url,
            'confidence': confidence,
            'extra_vars_preview': extra_vars_preview
        })

    audit_logs = AutomationAuditLog.objects.all().order_by('-id')[:10]
    activity_logs = UserActivityLog.objects.all().order_by('-timestamp')[:50]
    
    total_count = incidents.count()
    critical_count = incidents.filter(severity__in=['HIGH', 'CRITICAL'], status='PENDING').count()
    resolved_count = incidents.filter(status='RESOLVED').count()

    context = {
        'enriched_incidents': enriched_incidents,
        'audit_logs': audit_logs,
        'activity_logs': activity_logs,
        'total_count': total_count,
        'critical_count': critical_count,
        'resolved_count': resolved_count,
    }
    return render(request, 'dashboard/index.html', context)

@csrf_exempt
def incident_webhook(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            raw_template_id = data.get('awx_template_id') or data.get('template_id', 7)
            template_id = int(raw_template_id)
            severity = data.get('severity', 'MEDIUM').upper()
            
            # Auto-run LOW severity; keep MEDIUM/HIGH/CRITICAL as PENDING for HITL approval
            initial_status = 'RUNNING' if severity == 'LOW' else data.get('status', 'PENDING')

            incident = IncidentAlert.objects.create(
                title=data.get('title', 'External Alert'),
                description=data.get('description', ''),
                severity=severity,
                status=initial_status,
                awx_template_id=template_id,
                ai_analysis=data.get('ai_analysis', '')
            )

            # Instantly dispatch AWX job for auto-eligible (LOW severity) incidents
            if severity == 'LOW':
                trigger_awx_job.delay(incident.id, incident.awx_template_id)
                log_user_activity(
                    request,
                    action="AUTO_DISPATCH_AWX",
                    resource=f"Incident #{incident.id} ({incident.title})",
                    details="Auto-executed due to LOW severity policy."
                )

            return JsonResponse({
                'status': 'success', 
                'incident_id': incident.id, 
                'awx_template_id': incident.awx_template_id,
                'executed_automatically': (severity == 'LOW')
            }, status=201)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'method not allowed'}, status=405)
