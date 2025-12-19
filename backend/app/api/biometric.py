from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Dict, Any

from app.core.database import get_db
from app.core.redis import get_redis, RedisClient
from app.services import BiometricAnalyzer
from app.schemas import BiometricDataSubmit, BiometricAnalysisResult, BiometricType, MessageResponse
from app.api.deps import get_current_user, get_current_session
from app.models import User, Session

router = APIRouter(prefix="/biometric", tags=["Biometric"])


@router.post("/collect", response_model=MessageResponse)
async def collect_biometric_data(
    data: BiometricDataSubmit,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    analyzer = BiometricAnalyzer(db, redis)
    
    device_category = data.device_category or 'desktop'
    
    await analyzer.collect_biometric_data(
        user_id=user.id,
        session_id=session.id,
        data_type=data.data_type,
        raw_data=data.data,
        device_category=device_category
    )
    await db.commit()
    
    return MessageResponse(message=f"Collected {len(data.data)} {data.data_type.value} samples ({device_category})")


@router.post("/analyze", response_model=BiometricAnalysisResult)
async def analyze_behavior(
    data_type: BiometricType = None,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    analyzer = BiometricAnalyzer(db, redis)
    
    result = await analyzer.analyze_behavior(
        user_id=user.id,
        session_id=session.id,
        data_type=data_type
    )
    await db.commit()
    
    return result


@router.post("/update-profile", response_model=MessageResponse)
async def update_biometric_profile(
    data_type: BiometricType,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    analyzer = BiometricAnalyzer(db, redis)
    
    profile = await analyzer.update_profile(user.id, data_type)
    await db.commit()
    
    if profile:
        return MessageResponse(message=f"Profile updated with {profile.sample_count} samples")
    else:
        return MessageResponse(
            message=f"Not enough samples. Need {30} samples minimum.",
            success=False
        )


@router.get("/profile-status")
async def get_profile_status(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    analyzer = BiometricAnalyzer(db, redis)
    return await analyzer.get_profile_status(user.id)


@router.get("/debug-samples")
async def debug_samples(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    from sqlalchemy import func
    from app.models import BiometricData, BiometricProfile
    
    # Count samples per type
    bio_types = ["KEYSTROKE", "MOUSE", "TOUCH", "SENSOR_FUSION"]
    sample_info = {}
    
    for bio_type in bio_types:
        # Total count
        count_result = await db.execute(
            select(func.count(BiometricData.id)).where(
                BiometricData.user_id == user.id,
                BiometricData.data_type == bio_type
            )
        )
        total = count_result.scalar() or 0
        
        # Training data count
        training_result = await db.execute(
            select(func.count(BiometricData.id)).where(
                BiometricData.user_id == user.id,
                BiometricData.data_type == bio_type,
                BiometricData.is_training_data == True
            )
        )
        training = training_result.scalar() or 0
        
        # Last sample time
        last_result = await db.execute(
            select(BiometricData.timestamp).where(
                BiometricData.user_id == user.id,
                BiometricData.data_type == bio_type
            ).order_by(BiometricData.timestamp.desc()).limit(1)
        )
        last_row = last_result.first()
        last_time = last_row[0].isoformat() if last_row else None
        
        sample_info[bio_type] = {
            "total_samples": total,
            "training_samples": training,
            "last_collected": last_time,
            "min_required": 30,
            "ready": total >= 30
        }
    
    # Get profile info
    profiles_result = await db.execute(
        select(BiometricProfile).where(BiometricProfile.user_id == user.id)
    )
    profiles = profiles_result.scalars().all()
    
    profile_info = {}
    for p in profiles:
        profile_info[p.data_type] = {
            "sample_count": p.sample_count,
            "model_version": p.model_version,
            "ml_trained": p.profile_data.get("ml_trained", False) if p.profile_data else False,
            "last_updated": p.last_updated.isoformat() if p.last_updated else None
        }
    
    return {
        "user_id": str(user.id),
        "samples": sample_info,
        "profiles": profile_info,
        "summary": {
            "total_samples": sum(s["total_samples"] for s in sample_info.values()),
            "types_ready": sum(1 for s in sample_info.values() if s["ready"]),
            "ml_models_trained": sum(1 for p in profile_info.values() if p.get("ml_trained"))
        }
    }


@router.get("/trust-score")
async def get_current_trust_score(
    user: User = Depends(get_current_user),
    session: Session = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
) -> Dict[str, Any]:
    import logging
    logger = logging.getLogger(__name__)
    
    analyzer = BiometricAnalyzer(db, redis)
    
    # First, detect device category from buffer data in THIS session
    # Check what types of data are in the buffer
    desktop_types = ["KEYSTROKE_desktop", "MOUSE_desktop"]
    mobile_types = ["KEYSTROKE_mobile", "TOUCH_mobile", "SENSOR_FUSION_mobile"]
    
    has_desktop_data = False
    has_mobile_data = False
    
    for dt in desktop_types:
        data = await redis.get_biometric_buffer(str(session.id), dt)
        if data:
            has_desktop_data = True
            break
    
    for dt in mobile_types:
        data = await redis.get_biometric_buffer(str(session.id), dt)
        if data:
            has_mobile_data = True
            break
    
    # Determine current device category
    if has_mobile_data and not has_desktop_data:
        current_device = "mobile"
    elif has_desktop_data and not has_mobile_data:
        current_device = "desktop"
    elif has_desktop_data and has_mobile_data:
        current_device = "hybrid"
    else:
        # No data in buffer yet - return neutral
        return {
            "current_score": 1.0,
            "threshold": 0.7,
            "status": "normal",
            "session_id": str(session.id),
            "device_category": "unknown",
            "note": "no_recent_data",
            "note_message": "Недостатньо даних для аналізу. Продовжуйте взаємодію з системою."
        }
    
    # Check if user has trained profile for THIS device type
    profile_status = await analyzer.get_profile_status(user.id)
    has_desktop_profile = profile_status.get("device_status", {}).get("desktop", {}).get("trained", False)
    has_mobile_profile = profile_status.get("device_status", {}).get("mobile", {}).get("trained", False)
    
    # Check if we have profile for current device
    has_profile_for_device = (
        (current_device == "desktop" and has_desktop_profile) or
        (current_device == "mobile" and has_mobile_profile) or
        (current_device == "hybrid" and (has_desktop_profile or has_mobile_profile))
    )
    
    if not has_profile_for_device:
        # No profile for this device - return 100% with note
        return {
            "current_score": 1.0,
            "threshold": 0.7,
            "status": "normal",
            "session_id": str(session.id),
            "device_category": current_device,
            "note": "no_profile_for_device",
            "note_message": f"Профіль для {('ПК' if current_device == 'desktop' else 'мобільного')} ще не сформовано."
        }
    
    # Analyze recent behavior
    try:
        analysis_result = await analyzer.analyze_behavior(
            user_id=user.id,
            session_id=session.id,
            data_type=None,
            device_category=current_device if current_device != "hybrid" else None
        )
        
        score = analysis_result.trust_score
        
        # Check if we actually analyzed any data
        has_analyzed_data = (
            analysis_result.keystroke_score is not None or
            analysis_result.mouse_score is not None or
            analysis_result.touch_score is not None or
            analysis_result.sensor_score is not None
        )
        
        if not has_analyzed_data:
            return {
                "current_score": 1.0,
                "threshold": 0.7,
                "status": "normal",
                "session_id": str(session.id),
                "device_category": current_device,
                "note": "no_analyzed_data",
                "note_message": "Дані збираються, але ще не проаналізовані."
            }
        
        # Update session trust score
        session.trust_score = score
        await db.commit()
        
        # Cache the score
        await redis.set_trust_score(str(session.id), score)
        
    except Exception as e:
        logger.warning(f"Trust score analysis failed: {e}")
        cached_score = await redis.get_trust_score(str(session.id))
        score = cached_score if cached_score else session.trust_score

    critical_threshold = 0.5
    warning_threshold = 0.7
    
    status = "normal"
    if score < critical_threshold:
        status = "critical"
    elif score < warning_threshold:
        status = "warning"
    
    return {
        "current_score": score,
        "threshold": critical_threshold,
        "status": status,
        "session_id": str(session.id),
        "device_category": current_device
    }
