"""Django: the same purchase route behind django_middleware. In a project, put `commerce_check = django_middleware(...)` in
myapp/middleware.py and add "myapp.middleware.commerce_check" to MIDDLEWARE; the view reads request.agent_check."""
from django.http import JsonResponse

from openentity.commerce import django_middleware

from commerce_check_fastapi import POLICY, cart_for  # the same cart and policy as the FastAPI example


def buy(request):
    check = request.agent_check
    return JsonResponse({"bought": True, "agent": check.get("agent_did"), "evidence_id": check["evidence_id"]})


def make_middleware(cart=cart_for, policy=POLICY, **options):
    return django_middleware(cart=cart, policy=policy, paths=["/buy"], **options)
