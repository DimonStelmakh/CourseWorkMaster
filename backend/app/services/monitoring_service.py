from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from app.models import (
    User, Session, SecurityEvent, TrustScoreHistory,
    BiometricProfile, BiometricData, EventType, BiometricType
)
from app.core.config import settings
from app.core.redis import RedisClient


class MonitoringService:
    
    def __init__(self, db: AsyncSession, redis: RedisClient):
        self.db = db
        self.redis = redis
    
    async def get_user_dashboard(self, user_id: UUID) -> Dict[str, Any]:
        user_result = await self.db.execute(select(User).where(User.id == user_id))
        user = user_result.scalar_one_or_none()
        if not user:
            return None
        
        session_result = await self.db.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.is_active == True,
                Session.expires_at > datetime.utcnow()
            ).order_by(Session.last_activity.desc()).limit(1)
        )
        current_session = session_result.scalar_one_or_none()
        
        trust_history = await self._get_trust_score_history(user_id, hours=24)
        recent_events = await self._get_recent_events(user_id, limit=10)
        active_sessions = await self._get_active_sessions(user_id)
        profile_status = await self._get_profile_status(user_id)
        
        current_trust_score = current_session.trust_score if current_session else 1.0
        
        return {
            "user": {
                "id": str(user.id), "username": user.username, "email": user.email,
                "role": user.role, "is_verified": user.is_verified,
                "totp_enabled": user.totp_enabled
            },
            "current_trust_score": current_trust_score,
            "trust_score_threshold": settings.trust_score_threshold,
            "trust_score_history": trust_history,
            "recent_events": recent_events,
            "active_sessions": active_sessions,
            "profile_status": profile_status
        }
    
    async def _get_profile_status(self, user_id: UUID) -> Dict[str, Any]:
        from app.services.biometric_service import BiometricAnalyzer
        
        analyzer = BiometricAnalyzer(self.db, self.redis)
        return await analyzer.get_profile_status(user_id)
    
    async def get_admin_dashboard(self) -> Dict[str, Any]:
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        total_users = (await self.db.execute(select(func.count(User.id)))).scalar() or 0
        active_sessions = (await self.db.execute(
            select(func.count(Session.id)).where(Session.is_active == True, Session.expires_at > now)
        )).scalar() or 0
        events_today = (await self.db.execute(
            select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp >= today_start)
        )).scalar() or 0
        anomalies_today = (await self.db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.timestamp >= today_start,
                SecurityEvent.event_type == EventType.ANOMALY_DETECTED
            )
        )).scalar() or 0
        avg_trust = (await self.db.execute(
            select(func.avg(Session.trust_score)).where(Session.is_active == True)
        )).scalar() or 1.0
        
        return {
            "total_users": total_users, "active_sessions": active_sessions,
            "events_today": events_today, "anomalies_today": anomalies_today,
            "average_trust_score": float(avg_trust)
        }
    
    async def get_security_events(
        self, user_id: UUID = None, event_type: EventType = None,
        start_date: datetime = None, end_date: datetime = None,
        page: int = 1, page_size: int = 20
    ) -> Dict[str, Any]:
        query = select(SecurityEvent)
        count_query = select(func.count(SecurityEvent.id))
        
        filters = []
        if user_id:
            filters.append(SecurityEvent.user_id == user_id)
        if event_type:
            filters.append(SecurityEvent.event_type == event_type)
        if start_date:
            filters.append(SecurityEvent.timestamp >= start_date)
        if end_date:
            filters.append(SecurityEvent.timestamp <= end_date)
        
        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))
        
        total = (await self.db.execute(count_query)).scalar() or 0
        
        query = query.order_by(SecurityEvent.timestamp.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        
        result = await self.db.execute(query)
        events = result.scalars().all()
        
        return {
            "events": [
                {"id": str(e.id), "event_type": e.event_type,
                 "details": e.details, "ip_address": e.ip_address,
                 "timestamp": e.timestamp.isoformat()}
                for e in events
            ],
            "total": total, "page": page, "page_size": page_size
        }
    
    async def _get_trust_score_history(self, user_id: UUID, hours: int = 24) -> List[Dict]:
        since = datetime.utcnow() - timedelta(hours=hours)
        result = await self.db.execute(
            select(TrustScoreHistory).where(
                TrustScoreHistory.user_id == user_id,
                TrustScoreHistory.timestamp >= since
            ).order_by(TrustScoreHistory.timestamp.asc())
        )
        history = result.scalars().all()
        return [
            {"score": h.score, "keystroke_score": h.keystroke_score,
             "mouse_score": h.mouse_score, "touch_score": h.touch_score,
             "timestamp": h.timestamp.isoformat()}
            for h in history
        ]
    
    async def _get_recent_events(self, user_id: UUID, limit: int = 10) -> List[Dict]:
        result = await self.db.execute(
            select(SecurityEvent).where(SecurityEvent.user_id == user_id)
            .order_by(SecurityEvent.timestamp.desc()).limit(limit)
        )
        events = result.scalars().all()
        return [
            {"id": str(e.id), "event_type": e.event_type,
             "details": e.details, "timestamp": e.timestamp.isoformat()}
            for e in events
        ]
    
    async def _get_active_sessions(self, user_id: UUID) -> List[Dict]:
        result = await self.db.execute(
            select(Session).where(
                Session.user_id == user_id, Session.is_active == True,
                Session.expires_at > datetime.utcnow()
            ).order_by(Session.last_activity.desc())
        )
        sessions = result.scalars().all()
        return [
            {"id": str(s.id), "ip_address": s.ip_address, "user_agent": s.user_agent,
             "trust_score": s.trust_score, "start_time": s.start_time.isoformat(),
             "last_activity": s.last_activity.isoformat()}
            for s in sessions
        ]
    
    async def _calculate_profile_completion(self, user_id: UUID) -> float:
        from sqlalchemy import func
        from app.models import BiometricData, BiometricProfile
        
        # Count actual samples per type
        desktop_types = ["KEYSTROKE", "MOUSE"]
        mobile_types = ["TOUCH", "SENSOR_FUSION"]
        
        sample_counts = {}
        for bio_type in desktop_types + mobile_types:
            count_result = await self.db.execute(
                select(func.count(BiometricData.id)).where(
                    BiometricData.user_id == user_id,
                    BiometricData.data_type == bio_type
                )
            )
            sample_counts[bio_type] = count_result.scalar() or 0
        
        # Check which device category has data
        desktop_samples = sum(sample_counts.get(t, 0) for t in desktop_types)
        mobile_samples = sum(sample_counts.get(t, 0) for t in mobile_types)
        
        # Calculate completion based on the device category that has data
        min_samples = settings.min_training_samples
        
        if desktop_samples > 0 and mobile_samples == 0:
            # Desktop only - calculate desktop completion
            desktop_completion = min(
                (sample_counts.get("KEYSTROKE", 0) / min_samples) * 50 +
                (sample_counts.get("MOUSE", 0) / min_samples) * 50,
                100
            )
            return desktop_completion
            
        elif mobile_samples > 0 and desktop_samples == 0:
            # Mobile only - calculate mobile completion
            mobile_completion = min(
                (sample_counts.get("TOUCH", 0) / min_samples) * 50 +
                (sample_counts.get("SENSOR_FUSION", 0) / min_samples) * 50,
                100
            )
            return mobile_completion
            
        elif desktop_samples > 0 and mobile_samples > 0:
            # Both - average of both completions
            desktop_completion = min(
                (sample_counts.get("KEYSTROKE", 0) / min_samples) * 50 +
                (sample_counts.get("MOUSE", 0) / min_samples) * 50,
                100
            )
            mobile_completion = min(
                (sample_counts.get("TOUCH", 0) / min_samples) * 50 +
                (sample_counts.get("SENSOR_FUSION", 0) / min_samples) * 50,
                100
            )
            return (desktop_completion + mobile_completion) / 2
        
        return 0


class SecurityLogger:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def log_event(
        self, user_id: UUID, event_type: EventType,
        details: Dict = None, session_id: UUID = None,
        ip_address: str = None, user_agent: str = None
    ):
        event = SecurityEvent(
            user_id=user_id, session_id=session_id, event_type=event_type,
            details=details, ip_address=ip_address, user_agent=user_agent
        )
        self.db.add(event)
        await self.db.flush()
        return event
