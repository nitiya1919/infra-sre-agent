from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('api/webhook/', views.incident_webhook, name='incident_webhook'),
    path('login/', auth_views.LoginView.as_view(template_name='dashboard/login.html'), name='login'),
    path('logout/', views.custom_logout_view, name='logout'),
    path('incident/<int:incident_id>/post-mortem/', views.export_post_mortem, name='export_post_mortem'),
    path('analytics/', views.sre_analytics_dashboard, name='sre_analytics'),
]
