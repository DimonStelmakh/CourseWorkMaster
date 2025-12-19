from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import Optional, Dict, Any

from app.core.database import get_db
from app.core.redis import get_redis, RedisClient
from app.services import MonitoringService
from app.api.deps import get_current_user, get_current_admin
from app.models import User, EventType

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/user")
async def get_user_dashboard(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    monitoring = MonitoringService(db, redis)
    dashboard = await monitoring.get_user_dashboard(user.id)
    
    if not dashboard:
        raise HTTPException(status_code=404, detail="User not found")
    
    return dashboard


@router.get("/admin")
async def get_admin_dashboard(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    monitoring = MonitoringService(db, redis)
    return await monitoring.get_admin_dashboard()


@router.get("/events")
async def get_security_events(
    event_type: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    monitoring = MonitoringService(db, redis)
    
    evt_type = None
    if event_type:
        try:
            evt_type = EventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid event type")
    
    return await monitoring.get_security_events(
        user_id=user.id,
        event_type=evt_type,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size
    )


@router.get("/admin/events")
async def get_all_security_events(
    user_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    from uuid import UUID
    
    monitoring = MonitoringService(db, redis)
    
    evt_type = None
    if event_type:
        try:
            evt_type = EventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid event type")
    
    uid = None
    if user_id:
        try:
            uid = UUID(user_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid user ID")
    
    return await monitoring.get_security_events(
        user_id=uid,
        event_type=evt_type,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size
    )
