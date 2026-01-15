"""
Device discovery endpoints
ssh discovery
snmp v2
snmp v3
"""

"""
Import any custom utilities
"""
from app.network_utilities.icmp_check import pingOk

"""
Regular includes / imports etc.
"""
from uuid import uuid4

from starlette.status import HTTP_400_BAD_REQUEST, HTTP_403_FORBIDDEN
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field
from app.security.auth import UserContext, get_current_user, require_roles

from app.database import database
from app.database_queries.postgres_insert_queries import (insert_app_backend_tracking)

from app.celery_app import celery_app

from app.shared_functions.helpers.helpers import (
    user_display,
    scrub_secrets,
    _insert_job_row_queued
)

import logging
import ipaddress

logger = logging.getLogger("app.device_discovery")

router = APIRouter(
    prefix="/device_discovery",
    tags=["device_discovery"],
    dependencies=[Depends(get_current_user)]
)


"""
Classes
"""

class DiscoveryTarget(BaseModel):
    ipv4_address: str | None = Field(default=None, example="10.0.0.0/32")
    task: str | None = Field(default=None, example="ssh | snmpv2 | snmpv3")
    bypass_icmp: bool | None = Field(default=False, example="True: Bypass ICMP Check. The server will not attempt to ping the device when starting discovery.Otherwise if ICMP fails, the server will stop discovery.")

"""

NOTES:
There is a test script built to post to this endpoint if you want to use it and not setup
something in a different program. Change the values for the credentials to fit your setup.

Instructions on how to use are at the top of the file. 

backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh

"""

"""
Utility endpoints
"""
@router.post("/start_device_discovery", summary="Enqueue a device discovery job", status_code=200)
async def start_device_discovery(
    payload: DiscoveryTarget,
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    # roles (ANY-of)
    required = {"fastapi_client", "device_discovery_user"}
    if not required.intersection(set(user.roles or [])):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Insufficient role")

    if not payload.ipv4_address:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="ipv4_address is required")

    # normalize "10.0.0.1/32" -> "10.0.0.1"
    try:
        ipaddress.ip_network(payload.ipv4_address)
        target_ip = payload.ipv4_address.split("/")[0]
    except ValueError:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid ipv4_address")

    job_id = str(uuid4())
    requested_by = user_display(user)

    meta = {
        "job_id": job_id,
        "route": str(request.url.path),
        "requested_by": requested_by,
        "azp": getattr(user, "azp", None),
        "roles": user.roles or [],
        "target_ip": target_ip,
        "payload": scrub_secrets(payload.model_dump()),
    }

    # enqueue
    async_result = celery_app.send_task("device_discovery.start_device_discovery", args=[meta])
    celery_task_id = async_result.id

    # create job row immediately (so /celery_jobs/{job_id} works right away)
    await _insert_job_row_queued(
        job_id=job_id,
        task_id=celery_task_id,
        job_name="device_discovery.start_device_discovery",
        request_payload=meta,
    )

    # optional: log event in backend tracking table too
    await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "start_device_discovery_enqueued",
            "job_id": job_id,
            "celery_task_id": celery_task_id,
            "requested_by": requested_by,
            "azp": getattr(user, "azp", None),
            "roles": user.roles or [],
            "target_ip": target_ip,
        },
    )

    return {"detail": {"job_id": job_id, "celery_task_id": celery_task_id, "status": "QUEUED"}}
