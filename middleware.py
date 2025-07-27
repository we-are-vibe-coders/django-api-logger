import time
import re
import psutil
from django.conf import settings
from django.contrib.sessions.models import Session
from django.utils.deprecation import MiddlewareMixin
from django.utils.timezone import now
from .models import APIAccessLog, ClientFingerprint, AlertRecipient
from django.db import connection
from .utils.types import CheckingConditions
import json
from django.core.mail import send_mail

class APIMonitorMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        super().__init__(get_response)
        self.enable_alert_emails = getattr(settings, 'SEND_API_LOG_EMAILS', False)

        self.alert_types_by_role = {
            'owner': getattr(settings, 'OWNER_ALERT_TYPES', []),
            'admin': getattr(settings, 'ADMIN_ALERT_TYPES', []),
            'developer': getattr(settings, 'DEVELOPERS_ALERT_TYPES', []),
            'analyst': getattr(settings, 'ANALYST_ALERT_TYPES', []),
            'support': getattr(settings, 'SUPPORT_ALERT_TYPES', []),
            'other': getattr(settings, 'OTHER_USER_ALERT_TYPES', []),
        }
        self.start_time = 0
        self.query_count = 0

    def process_request(self, request):
        self.start_time = time.perf_counter()
        self.query_count = len(connection.queries)
        self._create_client_fingerprint(request)

    def process_response(self, request, response):
        try:
            api_access_log_instance = self._create_api_access_log(request, response)

            self.send_role_based_alerts(api_access_log_instance)

        except Exception as e:
            pass  # Avoid breaking app in case of logging error

        return response

    def _create_client_fingerprint(self, request):

        self.client_finger_print_instance = ClientFingerprint.objects.create(
            user = request.user if request.user.is_authenticated else None,
            cookie_data = request.COOKIES,
            token = request.META.get('HTTP_AUTHORIZATION', ''),
            ip_address = self._get_client_ip(request),
            user_agent = request.META.get('HTTP_USER_AGENT', ''),
            host = request.META.get('HTTP_HOST', ''),
            session_id = request.session.session_key or ''
        )

    def _create_api_access_log(self, request, response):
        execution_time = time.perf_counter() - self.start_time
        query_count = len(connection.queries) - self.query_count
        memory_usage = psutil.virtual_memory().used / (1024 ** 2)  # MB
        cpu_usage = psutil.cpu_percent()

        suspicious, reason = self.detect_suspicious(request)
        sql_injection, sql_pattern = self.detect_sql_injection(request)

        api_access_log_instance = APIAccessLog.objects.create(
            request_method=request.method,
            url_path=request.path,
            view_name=request.resolver_match.view_name if request.resolver_match else '',
            execution_time=execution_time,
            duration_bucket=self.get_duration_bucket(execution_time),
            memory_usage=round(memory_usage, 2),
            cpu_percent=cpu_usage,
            status_code=response.status_code,
            query_count=query_count,
            is_error=response.status_code >= 500,
            error_type='',
            error_description='',
            client_fingerprint=self.client_finger_print_instance,
            is_suspicious=suspicious,
            suspicious_reason=reason,
            is_sql_injection_suspected=sql_injection,
            sql_injection_pattern=sql_pattern,
            # is_rate_limited=False,  # handled by throttling or view
            # rate_limited_reason='',
            severity=self.map_severity(suspicious, sql_injection, response.status_code),
            timestamp=now()
        )

        return api_access_log_instance

    @staticmethod
    def detect_suspicious(request):
        # if request.method == 'POST' and len(request.body) > 10000:
        #     return True, 'Large POST body'
        if request.path.startswith('/admin/') and not request.user.is_authenticated:
            return True, 'Unauthorized admin access attempt'
        if Session.objects.filter(session_key=request.session.session_key, expire_date__gt=now()).exists():
            return True, 'Session duplicated detected'
        return False, ''

    @staticmethod
    def access_request_data(request):
        json_request = {}

        if request.method == 'GET':
            json_request.update(request.GET)
        elif request.method == 'POST':
            json_request.update(request.POST)
        elif request.method in ['PUT', 'PATCH', 'DELETE']:
            content_type = request.META.get('CONTENT_TYPE', '')
            if 'application/json' in content_type:
                try:
                    parsed = json.loads(request.body.decode('utf-8'))
                    if isinstance(parsed, dict):
                        json_request.update(parsed)
                except Exception:
                    pass

        return  json_request


    def detect_sql_injection(self,request):
        suspicious_patterns = []
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in
                             CheckingConditions.SQL_INJECTION_SUSPECTED_CONDITIONS.value]

        # Extract and flatten request data into a single string
        request_json_data = self.access_request_data(request)
        combined_text = " ".join(map(str, request_json_data.values()))

        # Search for matches
        for pattern in compiled_patterns:
            if pattern.search(combined_text):
                suspicious_patterns.append(pattern.pattern)
                # suspicious_patterns[request_json_data[pattern.pattern]] = pattern.search(combined_text)

        return bool(suspicious_patterns), ", ".join(suspicious_patterns)



    @staticmethod
    def _get_client_ip(request):
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded.split(',')[0] if x_forwarded else request.META.get('REMOTE_ADDR')

    @staticmethod
    def get_duration_bucket( seconds):
        if seconds < 0.1:
            return "<100ms"
        elif seconds < 0.5:
            return "<500ms"
        elif seconds < 1:
            return "<1s"
        elif seconds < 2:
            return "<2s"
        else:
            return ">2s"

    @staticmethod
    def map_severity(suspicious, sql, status_code):
        if status_code >= 500 or sql:
            return "critical"
        if suspicious:
            return "warning"
        return "info"


    def send_role_based_alerts(self,log_instance):
        recipients = set()

        for role, types in self.alert_types_by_role.items():
            if log_instance.severity in types:
                role_emails = AlertRecipient.objects.filter(designation=role).values_list('email', flat=True)
                recipients.update(role_emails)

        if recipients:
            send_mail(
                subject=log_instance.type + " Alert",
                message=json.dumps({
                    "log": log_instance.__dict__,
                    "fingerprint": self.client_finger_print_instance.__dict__,
                }, default=str),
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=list(recipients),
                fail_silently=False
            )