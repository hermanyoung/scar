from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

# ruleid: python.django.security.cwe-352.csrf-exempt
@csrf_exempt
def update_profile(request):
    return JsonResponse({"status": "ok"})

# ok: python.django.security.cwe-352.csrf-exempt
def safe_update_profile(request):
    return JsonResponse({"status": "ok"})
