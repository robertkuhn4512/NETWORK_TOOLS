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

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field
from app.security.auth import UserContext, get_current_user, require_roles

from app.database import database
from app.database_queries.postgres_insert_queries import (insert_app_backend_tracking)

from app.celery_app import celery_app

from app.shared_functions.helpers.helpers import (
    user_display,
    scrub_secrets
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

@router.post("/start_device_discovery", summary="Initiate a device discovery job. ", status_code=200)
async def discover_device_ipv4(
    payload: DiscoveryTarget,
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    #Hashing out for now - using the database.
    #logger.info(
    #    "device_discovery requested user=%s task=%s target=%s path=%s",
    #    getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
    #    payload.task,
    #    payload.ipv4_address,
    #    request.url.path,
    #)

    """
    Only user / service accounts pass when their account has any of the
    selected roles assigned to their account in keycloak
    
    fastapi_client          :: Role assigned to the account setup for the service account in fastapi
    device_discovery_user   :: Role assigned to a service / user account given to a user account
    """

    required = {"fastapi_client", "device_discovery_user"}

    if not required.intersection(set(user.roles or [])):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Insufficient role")

    # Validate submitted data
    proceed = False
    if payload.ipv4_address is not None:
        try:
            ipaddress.ip_network(payload.ipv4_address)
            target_ip = payload.ipv4_address.split('/')[0]

            db_log = await insert_app_backend_tracking(
                database=database,
                route=request.url.path,
                information={
                    "event": "device_discovery_start - Success - Valid Target IPv4 Address",
                    "requested_by": getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
                    "azp": getattr(user, "azp", None),
                    "roles": getattr(user, "roles", None),
                    "payload": scrub_secrets(payload.model_dump()),
                    "target_ip": target_ip,
                },
            )

            # Good to proceed to the next steps.
            proceed = True

            if "error" in db_log:
                logger.info(
                    "device_discovery database_error user=%s task=%s target=%s path=%s",
                    getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
                    payload.task,
                    payload.ipv4_address,
                    request.url.path,
                )
                return {"detail": {"status": "queued", "db_log_error": db_log["error"]}}

            return {
                    "event": "device_discovery_start - Success - Valid Target IPv4 Address",
                    "requested_by": getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
                    "azp": getattr(user, "azp", None),
                    "roles": getattr(user, "roles", None),
                    "payload": scrub_secrets(payload.model_dump()),
                    "target_ip": target_ip,
                }

        except ValueError as e:
            db_log = await insert_app_backend_tracking(
                database=database,
                route=request.url.path,
                information={
                    "event": "device_discovery_start - Failed - Invalid ipv4_address",
                    "requested_by": getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
                    "azp": getattr(user, "azp", None),
                    "roles": getattr(user, "roles", None),
                    "payload": scrub_secrets(payload.model_dump()),
                },
            )

            if "error" in db_log:
                logger.info(
                    "device_discovery database_error user=%s task=%s target=%s path=%s",
                    getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
                    payload.task,
                    payload.ipv4_address,
                    request.url.path,
                )
                return {"detail": {"status": "queued", "db_log_error": db_log["error"]}}

            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail="Invalid data submitted (ipv4_address)")


    requested_by = user_display(user)

    db_log = await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "device_discovery_start",
            "requested_by": getattr(user, "preferred_username", None) or getattr(user, "username", None) or getattr(user, "sub", "unknown"),
            "azp": getattr(user, "azp", None),
            "roles": getattr(user, "roles", None),
            "payload": scrub_secrets(payload.model_dump()),
        },
    )

    if "error" in db_log:
        return {"detail": {"status": "queued", "db_log_error": db_log["error"]}}

    return {
        "detail": {
            "requested_by": user.username,
            "client_id": user.azp,
            "payload": payload.model_dump(),
        }
    }

@router.post("/test_celery", summary="Enqueue a test Celery task.", status_code=200)
async def test_celery(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    job_id = str(uuid4())

    meta = {
        "job_id": job_id,
        "route": str(request.url.path),
        "requested_by": user.username,
        "azp": getattr(user, "azp", None),
        "roles": user.roles or [],
    }

    async_result = celery_app.send_task("tracking.test", args=[meta])

    logger.info("enqueued tracking.test job_id=%s celery_task_id=%s", job_id, async_result.id)

    return {"detail": {"job_id": job_id, "celery_task_id": async_result.id}}