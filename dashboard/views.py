import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import IncidentAlert, AutomationAuditLog
from .tasks import trigger_awx_job

@login_required
def dashboard_view(request):
    if request.method == 'POST':
        incident_id = request.POST.get('incident_id')
        if incident_id:
            incident = get_object_or_404(IncidentAlert, id=incident_id)
            trigger_awx_job.delay(incident.id, incident.awx_template_id)
            return redirect('dashboard')

    incidents = IncidentAlert.objects.all().order_by('-created_at')
    
    awx_base = settings.AWX_HOST or "http://localhost"
    awx_web_base = awx_base.split("/api/v2")[0] if "/api/v2" in awx_base else awx_base.rstrip('/')

    enriched_incidents = []
    for inc in incidents:
        latest_log = AutomationAuditLog.objects.filter(incident=inc).order_by('-executed_at').first()
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

    audit_logs = AutomationAuditLog.objects.all().order_by('-executed_at')[:10]
    
    total_count = incidents.count()
    critical_count = incidents.filter(severity__in=['HIGH', 'CRITICAL'], status='PENDING').count()
    resolved_count = incidents.filter(status='RESOLVED').count()

    context = {
        'enriched_incidents': enriched_incidents,
        'audit_logs': audit_logs,
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
            incident = IncidentAlert.objects.create(
                title=data.get('title', 'External Alert'),
                description=data.get('description', ''),
                severity=data.get('severity', 'MEDIUM'),
                status=data.get('status', 'PENDING'),
                awx_template_id=template_id,
                ai_analysis=data.get('ai_analysis', '')
            )
            return JsonResponse({
                'status': 'success', 
                'incident_id': incident.id, 
                'awx_template_id': incident.awx_template_id
            }, status=201)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'method not allowed'}, status=405)
