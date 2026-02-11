"""
Device reporting endpoints
"""

from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.security.auth import UserContext, get_current_user
from app.database import database
from app.database_queries.postgres_select_queries import (
    fetch_device_listing,
    fetch_devices_datatable,
    fetch_device_backup_locations_datatable,
)

from app.database_queries.postgres_insert_queries import insert_app_backend_tracking
from app.shared_functions.helpers.helpers_authentication import user_display

router = APIRouter(
    prefix="/device_reporting",
    tags=["device_reporting"],
    dependencies=[Depends(get_current_user)],
)

class DeviceListingRequest(BaseModel):
    device_name: str | None = Field(default=None, example="test_device_1")
    ipv4_loopback: str | None = Field(default=None, example="10.0.0.1")
    backup_limit: int | None = Field(default=25, ge=0, example=25)

class DataTablesSearch(BaseModel):
    value: str | None = None
    regex: bool | None = False


class DataTablesOrder(BaseModel):
    column: int | None = 0
    dir: str | None = "asc"


class DataTablesColumn(BaseModel):
    data: str | None = None
    name: str | None = None
    searchable: bool | None = True
    orderable: bool | None = True
    search: DataTablesSearch | None = None


class DataTablesRequest(BaseModel):
    """
    Notes / How to run:
      - This is the standard DataTables server-side request payload.
      - DataTables should POST JSON to this endpoint (content-type: application/json).
    """
    draw: int | None = 0
    start: int | None = 0
    length: int | None = 25
    search: DataTablesSearch | None = None
    order: list[DataTablesOrder] | None = None
    columns: list[DataTablesColumn] | None = None

    model_config = {"extra": "allow"}

@router.post("/get_device_listing", summary="Fetch device row + backup locations", status_code=200)
async def get_device_listing(
    payload: DeviceListingRequest,
    request: Request,
    user: UserContext = Depends(get_current_user),
):

    required = {"fastapi_client", "device_listing_user"}

    if not required.intersection(set(user.roles or [])):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Insufficient role")

    res = await fetch_device_listing(
        database=database,
        device_name=payload.device_name,
        ipv4_loopback=payload.ipv4_loopback,
        backup_limit=payload.backup_limit,
    )

    if res.get("error"):
        err = res.get("error")
        status = HTTP_400_BAD_REQUEST

        if err == "devices_conflict_multiple_matches":
            status = HTTP_409_CONFLICT
        elif err == "database_error":
            status = HTTP_500_INTERNAL_SERVER_ERROR

        # FastAPI will wrap this as {"detail": <dict>}
        raise HTTPException(status_code=status, detail=res)

    await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "device_listing.get_device_listing",
            "requested_by": user_display(user),
            "azp": getattr(user, "azp", None),
            "roles": user.roles or [],
            "input": payload.model_dump(),
            "device_found": res.get("device_found"),
            "backup_count": res.get("backup_count"),
            "backup_limit": res.get("backup_limit"),
        },
    )

    return {"detail": res}

@router.post("/datatable/devices", summary="DataTables server-side: devices", status_code=200)
async def datatable_devices(
    body: DataTablesRequest,
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    required = {"fastapi_client", "device_listing_user"}
    if not required.intersection(set(user.roles or [])):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Insufficient role")

    res = await fetch_devices_datatable(database=database, dt=body.model_dump())

    if res.get("error"):
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=res)

    await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "device_reporting.datatable_devices",
            "requested_by": user_display(user),
            "azp": getattr(user, "azp", None),
            "roles": user.roles or [],
            "dt_meta": (res.get("meta") or {}),
            "counts": {
                "recordsTotal": res.get("recordsTotal"),
                "recordsFiltered": res.get("recordsFiltered"),
                "rows_returned": len(res.get("data") or []),
            },
        },
    )

    return {"detail": res}


@router.post("/datatable/device_backup_locations", summary="DataTables server-side: device_backup_locations", status_code=200)
async def datatable_device_backup_locations(
    body: DataTablesRequest,
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    required = {"fastapi_client", "device_listing_user"}
    if not required.intersection(set(user.roles or [])):
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Insufficient role")

    res = await fetch_device_backup_locations_datatable(database=database, dt=body.model_dump())

    if res.get("error"):
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=res)

    await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "device_reporting.datatable_device_backup_locations",
            "requested_by": user_display(user),
            "azp": getattr(user, "azp", None),
            "roles": user.roles or [],
            "dt_meta": (res.get("meta") or {}),
            "counts": {
                "recordsTotal": res.get("recordsTotal"),
                "recordsFiltered": res.get("recordsFiltered"),
                "rows_returned": len(res.get("data") or []),
            },
        },
    )

    return {"detail": res}