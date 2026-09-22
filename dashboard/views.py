import json
import re
from datetime import timedelta
import requests
from requests.auth import HTTPBasicAuth

from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Count, Q, Case, When, IntegerField
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout

from .models import IncidentAlert, AutomationAuditLog, UserActivityLog
from .tasks import trigger_awx_job


@csrf_exempt
def custom_logout_view(request):
    """Bypasses CSRF token mismatches specifically for user logout."""
    if request.method == 'POST':
        logout(request)
    return redirect('login')


def log_user_activity(request, action, resource, details=""):
    user = request.user if request.user.is_authenticated else None
    
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
        
    UserActivityLog.objects.create(
        user=user,
        action=action,
        resource=resource,
        ip_address=ip,
        details=details
    )


@login_required
def export_post_mortem(request, incident_id):
    """
    Generates an automated, compliance-ready Markdown post-mortem report 
    combining incident metadata, agent analysis, and audit logs.
    """
    incident = get_object_or_404(IncidentAlert, id=incident_id)
    audit_logs = AutomationAuditLog.objects.filter(incident=incident).order_by('-id')

    log_user_activity(
        request,
        action="EXPORT_POST_MORTEM",
        resource=f"Incident #{incident.id} ({incident.title})"
    )

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
        "## 2. Gemini Agent Advisory & RCA",
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
        "_Report generated autonomously by Agentic SRE Platform._"
    ])

    markdown_content = "\n".join(report_lines)

    response = HttpResponse(markdown_content, content_type='text/markdown')
    response['Content-Disposition'] = f'attachment; filename="post-mortem-incident-{incident.id}.md"'
    return response


@login_required
def dashboard_view(request):
    if request.method == 'POST':
        incident_id = request.POST.get('incident_id')
        if incident_id:
            incident = get_object_or_404(IncidentAlert, id=incident_id)
            action = request.POST.get('action')

            if action == 'cancel_job':
                job_id = None
                raw_job_id_field = ""
                
                # Strategy 1: Search all audit logs for this incident to find a valid job ID or job URL
                audit_logs = AutomationAuditLog.objects.filter(incident=incident).order_by('-id')
                for audit in audit_logs:
                    val = str(audit.awx_job_id or "")
                    matches = re.findall(r'\d+', val)
                    if matches:
                        job_id = matches[-1]
                        raw_job_id_field = val
                        break

                awx_base = (settings.AWX_HOST or "http://localhost").rstrip('/')
                awx_web_base = awx_base.split("/api/v2")[0] if "/api/v2" in awx_base else awx_base
                awx_user = getattr(settings, 'AWX_USERNAME', 'admin')
                awx_password = getattr(settings, 'AWX_PASSWORD', '')

                # Strategy 2: If no job ID found in logs, actively query AWX API for running/pending jobs for this template
                if not job_id and incident.awx_template_id:
                    try:
                        jobs_url = f"{awx_web_base}/api/v2/job_templates/{incident.awx_template_id}/jobs/?status__in=running,pending,waiting,queued"
                        res = requests.get(jobs_url, auth=HTTPBasicAuth(awx_user, awx_password), verify=False, timeout=5)
                        if res.status_code == 200:
                            data = res.json()
                            results = data.get('results', [])
                            if results:
                                job_id = str(results[0].get('id'))
                    except Exception as e:
                        print(f"Failed to query active AWX jobs: {e}")

                canceled_successfully = False
                if job_id:
                    is_workflow = 'workflow' in raw_job_id_field.lower()
                    endpoints = [
                        f"{awx_web_base}/api/v2/workflow_jobs/{job_id}/cancel/" if is_workflow else f"{awx_web_base}/api/v2/jobs/{job_id}/cancel/",
                        f"{awx_web_base}/api/v2/jobs/{job_id}/cancel/",
                        f"{awx_web_base}/api/v2/workflow_jobs/{job_id}/cancel/"
                    ]
                    
                    for cancel_url in endpoints:
                        try:
                            response = requests.post(
                                cancel_url, 
                                auth=HTTPBasicAuth(awx_user, awx_password), 
                                verify=False,
                                timeout=5
                            )
                            print(f"AWX Cancel URL: {cancel_url} -> Status: {response.status_code}, Body: {response.text}")
                            if response.status_code in [200, 202, 204]:
                                canceled_successfully = True
                                break
                        except Exception as e:
                            print(f"AWX Cancel Exception on {cancel_url}: {e}")
                            continue

                # Update local state and record audit log
                incident.status = 'CANCELLED'
                incident.save()

                latest_audit = audit_logs.first()
                AutomationAuditLog.objects.create(
                    incident=incident,
                    awx_job_id=job_id or (latest_audit.awx_job_id if latest_audit else "Unknown"),
                    status=f"[INFO] Job execution aborted by operator command. AWX Cancelled: {canceled_successfully}"
                )

                log_user_activity(
                    request,
                    action="CANCEL_AWX_JOB",
                    resource=f"Incident #{incident.id} ({incident.title})",
                    details=f"Operator aborted AWX Job ID #{job_id or 'Unknown'}. Success: {canceled_successfully}."
                )
                return redirect('dashboard')

            if incident.severity in ['HIGH', 'CRITICAL'] and not (request.user.is_staff or request.user.is_superuser):
                log_user_activity(
                    request,
                    action="UNAUTHORIZED_TRIGGER_ATTEMPT",
                    resource=f"Incident #{incident.id} ({incident.title})",
                    details="Non-admin user attempted to authorize high/critical remediation."
                )
                return HttpResponse("Unauthorized: SRE Admin privileges required to authorize critical playbooks.", status=403)
            
            action_type = "RETRY_REMEDIATION" if incident.status in ['FAILED', 'TIMED_OUT', 'CANCELLED'] else "TRIGGER_AWX"
            
            incident.status = 'CONNECTING'
            incident.save()
            
            trigger_awx_job.delay(incident.id, incident.awx_template_id)
            
            log_user_activity(
                request,
                action=action_type,
                resource=f"Incident #{incident.id} ({incident.title})"
            )
            
            return redirect('dashboard')

    # --- FILTER HANDLING FOR METRIC CARDS ---
    current_filter = request.GET.get('filter', 'all')
    incidents_qs = IncidentAlert.objects.all()

    if current_filter == 'critical':
        incidents_qs = incidents_qs.filter(severity__in=['HIGH', 'CRITICAL'], status='PENDING')
    elif current_filter == 'resolved':
        incidents_qs = incidents_qs.filter(status__iexact='RESOLVED')

    incidents = list(incidents_qs.order_by('-created_at')[:100])
    
    awx_base = settings.AWX_HOST or "http://localhost"
    awx_web_base = awx_base.split("/api/v2")[0] if "/api/v2" in awx_base else awx_base.rstrip('/')

    template_stats = IncidentAlert.objects.values('awx_template_id').annotate(
        total_runs=Count('id'),
        successful_runs=Count(Case(When(status__iexact='RESOLVED', then=1), output_field=IntegerField()))
    )
    template_success_map = {}
    for stat in template_stats:
        t_id = stat['awx_template_id']
        total = stat['total_runs']
        success = stat['successful_runs']
        if total > 0:
            template_success_map[t_id] = int((success / total) * 100)
        else:
            template_success_map[t_id] = 85

    incident_ids = [inc.id for inc in incidents]
    audit_log_map = {}
    if incident_ids:
        recent_logs = AutomationAuditLog.objects.filter(incident_id__in=incident_ids).order_by('-id')
        for log in recent_logs:
            if log.incident_id not in audit_log_map:
                audit_log_map[log.incident_id] = log

    enriched_incidents = []
    for inc in incidents:
        latest_log = audit_log_map.get(inc.id)
        full_error = latest_log.status if (inc.status in ['FAILED', 'TIMED_OUT'] and latest_log) else None
        
        awx_template_url = f"{awx_web_base}/#/templates/job_template/{inc.awx_template_id}"
        
        base_confidence = template_success_map.get(inc.awx_template_id, 88)
        confidence = min(max(base_confidence + (inc.id % 5), 50), 99)

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
    
    total_count = IncidentAlert.objects.count()
    critical_count = IncidentAlert.objects.filter(severity__in=['HIGH', 'CRITICAL'], status='PENDING').count()
    resolved_count = IncidentAlert.objects.filter(status='RESOLVED').count()

    context = {
        'enriched_incidents': enriched_incidents,
        'audit_logs': audit_logs,
        'activity_logs': activity_logs,
        'total_count': total_count,
        'critical_count': critical_count,
        'resolved_count': resolved_count,
        'current_filter': current_filter,
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
            
            initial_status = 'CONNECTING' if severity == 'LOW' else data.get('status', 'PENDING')

            incident = IncidentAlert.objects.create(
                title=data.get('title', 'External Alert'),
                description=data.get('description', ''),
                severity=severity,
                status=initial_status,
                awx_template_id=template_id,
                ai_analysis=data.get('ai_analysis', '')
            )

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


@login_required
def sre_analytics_dashboard(request):
    try:
        days_filter = int(request.GET.get('days', 7))
    except ValueError:
        days_filter = 7

    since_date = timezone.now() - timedelta(days=days_filter)

    if hasattr(IncidentAlert, 'created_at'):
        incidents = IncidentAlert.objects.filter(created_at__gte=since_date)
    else:
        incidents = IncidentAlert.objects.all()

    total_incidents = incidents.count()

    unauthorized_count = incidents.filter(
        Q(ai_analysis__icontains='401') | 
        Q(ai_analysis__icontains='Unauthorized') | 
        Q(description__icontains='401') | 
        Q(description__icontains='Unauthorized')
    ).count()
    
    not_found_count = incidents.filter(
        Q(ai_analysis__icontains='404') | 
        Q(ai_analysis__icontains='No JobTemplate') | 
        Q(description__icontains='404') | 
        Q(description__icontains='No JobTemplate')
    ).count()

    resolved_count = incidents.filter(status__iexact='RESOLVED').count()
    success_rate = round((resolved_count / total_incidents * 100) if total_incidents > 0 else 0, 1)

    template_rankings = list(
        incidents.filter(status__iexact='RESOLVED')
        .values('awx_template_id')
        .annotate(success_count=Count('id'))
        .order_by('-success_count')
    )
    
    max_success = max([item['success_count'] for item in template_rankings], default=1)
    for item in template_rankings:
        item['percentage'] = int((item['success_count'] / max_success) * 100)

    incident_summary = (
        incidents.values('title', 'status')
        .annotate(total=Count('id'))
        .order_by('-total')
    )

    context = {
        'days_filter': days_filter,
        'total_incidents': total_incidents,
        'success_rate': success_rate,
        'unauthorized_count': unauthorized_count,
        'not_found_count': not_found_count,
        'template_rankings': template_rankings,
        'incident_summary': incident_summary,
    }
    return render(request, 'dashboard/analytics.html', context)
