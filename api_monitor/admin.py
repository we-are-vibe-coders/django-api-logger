from django.conf import settings
from django.contrib import admin
from django.shortcuts import render
from django.http import HttpResponse
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
import csv

from .models import APIAccessLog, AlertRecipient


@admin.register(APIAccessLog)
class APIAccessLogAdmin(admin.ModelAdmin):
    list_display = (
        # 'api_request_log_user_log__user__username',
        'view_name',
        'url_path',
        'request_method',
        'memory_usage',
        'cpu_percent',
        'is_error',
        'is_suspicious',
        'is_sql_injection_suspected',
        # 'is_rate_limited',
        'timestamp',
    )
    search_fields = (
        # 'api_request_log_user_log__user__username',
        'view_name',
        'url_path',
        'request_method',
        'memory_usage',
        'cpu_percent',
        'is_error',
        'is_suspicious',
        'is_sql_injection_suspected',
        # 'is_rate_limited',
        'timestamp',
    )
    list_filter = (
        'status_code',
        'request_method',
        'is_error',
        'is_suspicious',
        'is_sql_injection_suspected',
        # 'is_rate_limited',
        'timestamp',
    )

    actions = ['export_as_csv', 'delete_old_logs', 'navigate_alert_recipient_create']

    def navigate_alert_recipient_create(self, request):
        return render(request, 'admin/add_alert_recipient.html')
    navigate_alert_recipient_create.short_description = "Add Alert Recipient"

    def export_as_csv(self, request, queryset):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="api_logs.csv"'
        writer = csv.writer(response)
        writer.writerow([
            'timestamp', 'request_method', 'url_path', 'status_code', 'view_name',
            'user', 'token', 'ip_address', 'user_agent', 'country', 'session_id',
            'cookie_data', 'execution_time', 'duration_bucket', 'memory_usage',
            'cpu_percent', 'query_count', 'is_error', 'error_type', 'error_description',
            'is_suspicious', 'suspicious_reason', 'is_sql_injection_suspected',
            'sql_injection_pattern', 'rate_limited_reason'
        ])
        for data in queryset:
            user_log = getattr(data, 'api_request_log_user_log', None)
            writer.writerow([
                data.timestamp,
                data.request_method,
                data.url_path,
                data.status_code,
                data.view_name,
                getattr(user_log.user, 'username', '') if user_log else '',
                getattr(user_log, 'token', '') if user_log else '',
                getattr(user_log, 'ip_address', '') if user_log else '',
                getattr(user_log, 'user_agent', '') if user_log else '',
                getattr(user_log, 'country', '') if user_log else '',
                getattr(user_log, 'session_id', '') if user_log else '',
                getattr(user_log, 'cookie_data', '') if user_log else '',
                data.execution_time,
                data.duration_bucket,
                data.memory_usage,
                data.cpu_percent,
                data.query_count,
                data.is_error,
                data.error_type,
                data.error_description,
                data.is_suspicious,
                data.suspicious_reason,
                data.is_sql_injection_suspected,
                getattr(data, 'sql_injection_pattern', ''),
                # data.is_rate_limited,
                getattr(data, 'rate_limited_reason', ''),
            ])
        return response
    export_as_csv.short_description = "Export Selected to CSV"

    def delete_old_logs(self, request, queryset):
        days = int(request.GET.get('days', 30))
        cutoff = timezone.now() - timedelta(days=days)
        deleted_count, _ = APIAccessLog.objects.filter(timestamp__lt=cutoff).delete()
        self.message_user(request, f"{deleted_count} old logs deleted successfully.")
    delete_old_logs.short_description = "Delete Logs Older Than 30 Days"

    def send_email_notifications(self, request, queryset):
        recipients = list(AlertRecipient.objects.values_list('email', flat=True))
        if not recipients:
            self.message_user(request, "No alert recipients configured.", level='error')
            return
        send_mail(
            subject='Suspicious API Activity Detected',
            message='Unusual API activity has been logged. Please check your dashboard.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )
        self.message_user(request, "Email notifications sent.")
    send_email_notifications.short_description = "Send Alert Email to Recipients"


@admin.register(AlertRecipient)
class AlertRecipientAdmin(admin.ModelAdmin):
    list_display = ('email', 'designation', 'created_at', 'created_by')
    search_fields = ('email', 'designation')
    list_filter = ('email', 'designation', 'created_at')

