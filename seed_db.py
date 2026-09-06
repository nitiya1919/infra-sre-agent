import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sre_platform.settings')
django.setup()

from django.contrib.auth.models import User
from dashboard.models import IncidentAlert

if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print('Superuser created: admin / admin123')

if IncidentAlert.objects.count() == 0:
    IncidentAlert.objects.create(
        title='AWS ECR Image Vulnerability Spike',
        description='Critical CVE discovered across 14 container images in us-east-1 registry.',
        severity='HIGH',
        status='PENDING',
        ai_analysis='Recommended action: Run automated AWX patch playbook to sweep stale tags and trigger rolling container builds.'
    )
    print('Sample incidents seeded successfully.')
