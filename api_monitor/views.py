# from django.db.models import Count, Avg
# from django.http import JsonResponse
# from .models import APIRequestLog
# from django.contrib.admin.views.decorators import staff_member_required
#
# @staff_member_required
# def usage_stats_view(request):
#     top_endpoints = (APIRequestLog.objects
#                      .values('path')
#                      .annotate(count=Count('id'), avg_time=Avg('execution_time'))
#                      .order_by('-count')[:10])
#
#     top_users = (APIRequestLog.objects
#                  .values('user__username')
#                  .annotate(count=Count('id'))
#                  .order_by('-count')[:10])
#
#     return JsonResponse({
#         'top_endpoints': list(top_endpoints),
#         'top_users': list(top_users),
#     })
