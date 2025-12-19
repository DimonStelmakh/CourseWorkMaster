from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any
from uuid import UUID
import secrets

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.models import User, Session, SecurityEvent, EventType, UserRole
from app.core.security import (
    verify_password, 
    get_password_hash, 
    create_access_token,
    generate_session_token,
    generate_verification_token,
    generate_totp_secret,
    generate_totp_qr_code,
    verify_totp,
    generate_backup_codes,
    hash_backup_codes,
    verify_backup_code
)
from app.core.config import settings
from app.core.redis import RedisClient
from app.schemas import UserCreate, LoginRequest, UserResponse
from app.services.email_service import email_service


class AuthenticationService:
    def __init__(self, db: AsyncSession, redis: RedisClient):
        self.db = db
        self.redis = redis
    
    async def register_user(self, user_data: UserCreate) -> User:
        # Check if username or email exists
        existing = await self.db.execute(
            select(User).where(
                (User.username == user_data.username) | 
                (User.email == user_data.email)
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("Username or email already exists")
        
        # Create user
        verification_token = generate_verification_token()
        user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=get_password_hash(user_data.password),
            email_verification_token=verification_token,
            email_verification_expires=datetime.utcnow() + timedelta(hours=24)
        )
        
        self.db.add(user)
        await self.db.flush()
        
        # Send verification email (async, don't wait)
        await email_service.send_email_verification(
            user.email, 
            user.username, 
            verification_token
        )
        
        # Log event
        await self._log_event(user.id, EventType.LOGIN_SUCCESS, {"action": "registration"})
        
        return user
    
    async def authenticate(
        self, 
        login_data: LoginRequest,
        ip_address: str = None,
        user_agent: str = None
    ) -> Tuple[User, bool, Optional[str], Optional[str], Optional[float]]:
        # Find user
        result = await self.db.execute(
            select(User).where(User.username == login_data.username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("Invalid username or password")
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise ValueError(f"Account is locked until {user.locked_until}")
        
        # Verify password
        if not verify_password(login_data.password, user.password_hash):
            await self._handle_failed_login(user, ip_address, user_agent)
            raise ValueError("Invalid username or password")
        
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.locked_until = None
        
        # If MFA is not enabled, allow login
        if not user.totp_enabled:
            await self._log_event(
                user.id,
                EventType.LOGIN_SUCCESS,
                {"ip": ip_address, "mfa_enabled": False},
                ip_address=ip_address,
                user_agent=user_agent
            )
            return user, False, None, None, None
        
        # MFA is enabled - check biometric profile
        biometric_result = await self._analyze_login_biometrics(
            user.id, 
            login_data.biometric_data
        )
        
        trust_score = biometric_result.get("trust_score")
        
        # Decision based on biometric analysis
        if biometric_result["can_skip_mfa"]:
            # Biometric profile matches - skip MFA
            await self._log_event(
                user.id,
                EventType.LOGIN_SUCCESS,
                {
                    "ip": ip_address, 
                    "mfa_skipped": True, 
                    "reason": "biometric_match",
                    "trust_score": trust_score
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            return user, False, None, None, trust_score
        
        # Need MFA - generate token
        mfa_token = secrets.token_urlsafe(32)
        await self.redis.client.setex(
            f"mfa_pending:{mfa_token}",
            300,  # 5 minutes expiry
            str(user.id)
        )
        
        mfa_reason = biometric_result.get("reason", "verification_required")
        
        await self._log_event(
            user.id, 
            EventType.MFA_TRIGGERED,
            {
                "ip": ip_address, 
                "reason": mfa_reason,
                "trust_score": trust_score,
                "details": biometric_result.get("details")
            },
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return user, True, mfa_token, mfa_reason, trust_score
    
    async def _analyze_login_biometrics(
        self, 
        user_id: UUID, 
        biometric_data: Optional[Dict]
    ) -> Dict[str, Any]:
        from app.models import BiometricProfile
        from app.ml.models import BiometricMLModel
        import logging
        logger = logging.getLogger(__name__)
        
        # Get device category from biometric data
        device_category = biometric_data.get("device_category", "desktop") if biometric_data else "desktop"
        
        logger.info(f"=== LOGIN BIOMETRIC ANALYSIS ===")
        logger.info(f"User: {user_id}, Device category: {device_category}")
        
        # Check if user has any trained biometric profiles for this device category
        # For desktop, also include profiles where device_category is NULL (legacy)
        if device_category == "desktop":
            result = await self.db.execute(
                select(BiometricProfile).where(
                    BiometricProfile.user_id == user_id,
                    (BiometricProfile.device_category == device_category) |
                    (BiometricProfile.device_category.is_(None))
                )
            )
        else:
            result = await self.db.execute(
                select(BiometricProfile).where(
                    BiometricProfile.user_id == user_id,
                    BiometricProfile.device_category == device_category
                )
            )
        profiles = result.scalars().all()
        
        logger.info(f"Found {len(profiles)} profiles for device_category={device_category}")
        for p in profiles:
            logger.info(f"  - Profile: {p.data_type}, device_cat={p.device_category}, ml_trained={p.profile_data.get('ml_trained') if p.profile_data else None}")
        
        # Build profile lookup: (data_type, device_category) -> profile
        trained_profiles = {
            p.data_type: p for p in profiles 
            if p.profile_data and p.profile_data.get("ml_trained")
        }
        
        logger.info(f"Trained profiles for {device_category}: {list(trained_profiles.keys())}")
        
        # No trained profiles for this device - require MFA
        if not trained_profiles:
            # Check if user has profiles for OTHER device type
            other_device = "mobile" if device_category == "desktop" else "desktop"
            other_result = await self.db.execute(
                select(BiometricProfile).where(
                    BiometricProfile.user_id == user_id,
                    BiometricProfile.device_category == other_device
                )
            )
            other_profiles = other_result.scalars().all()
            has_other_profile = any(p.profile_data and p.profile_data.get("ml_trained") for p in other_profiles)
            
            if has_other_profile:
                return {
                    "can_skip_mfa": False,
                    "reason": "no_profile_for_device",
                    "trust_score": None,
                    "details": f"No trained profile for {device_category}. You have a profile for {other_device}."
                }
            else:
                return {
                    "can_skip_mfa": False,
                    "reason": "no_biometric_profile",
                    "trust_score": None,
                    "details": "No trained biometric profile exists"
                }
        
        # No biometric data provided with login - require MFA
        if not biometric_data:
            logger.info("No biometric data provided with login")
            return {
                "can_skip_mfa": False,
                "reason": "no_biometric_data",
                "trust_score": None,
                "details": "No biometric data provided during login"
            }
        
        logger.info(f"Received biometric types: {[k for k in biometric_data.keys() if k != 'device_category']}")
        
        # Analyze provided biometric data against profiles
        scores = []
        details = {}
        
        # Check keystroke data
        if "keystroke" in biometric_data and "KEYSTROKE" in trained_profiles:
            profile = trained_profiles["KEYSTROKE"]
            try:
                model = BiometricMLModel.deserialize(profile.profile_data["ml_model"])
                features = self._extract_keystroke_features(biometric_data["keystroke"])
                logger.info(f"Keystroke features extracted: {features}")
                if features:
                    trust, analysis = model.predict(features)
                    logger.info(f"Keystroke trust: {trust:.3f}, analysis: {analysis}")
                    scores.append(("KEYSTROKE", trust))
                    details["keystroke"] = {
                        "trust_score": trust,
                        "analysis": analysis
                    }
            except Exception as e:
                logger.error(f"Keystroke analysis error: {e}")
                details["keystroke_error"] = str(e)
        
        # Check mouse data
        if "mouse" in biometric_data and "MOUSE" in trained_profiles:
            profile = trained_profiles["MOUSE"]
            try:
                model = BiometricMLModel.deserialize(profile.profile_data["ml_model"])
                features = self._extract_mouse_features(biometric_data["mouse"])
                logger.info(f"Mouse features extracted: {features}")
                if features:
                    trust, analysis = model.predict(features)
                    logger.info(f"Mouse trust: {trust:.3f}, analysis: {analysis}")
                    scores.append(("MOUSE", trust))
                    details["mouse"] = {
                        "trust_score": trust,
                        "analysis": analysis
                    }
            except Exception as e:
                logger.error(f"Mouse analysis error: {e}")
                details["mouse_error"] = str(e)
        
        # Check touch data (for mobile)
        if "touch" in biometric_data and "TOUCH" in trained_profiles:
            profile = trained_profiles["TOUCH"]
            try:
                model = BiometricMLModel.deserialize(profile.profile_data["ml_model"])
                # Use basic touch features
                features = self._extract_touch_features(biometric_data["touch"])
                if features:
                    trust, analysis = model.predict(features)
                    logger.info(f"Touch trust: {trust:.3f}")
                    scores.append(("TOUCH", trust))
                    details["touch"] = {"trust_score": trust, "analysis": analysis}
            except Exception as e:
                logger.error(f"Touch analysis error: {e}")
                details["touch_error"] = str(e)
        
        # For desktop: REQUIRE BOTH keystroke AND mouse profiles
        # For mobile: REQUIRE ALL THREE: keystroke, touch, sensor
        if device_category == "desktop":
            required_types = ["KEYSTROKE", "MOUSE"]
            has_all_required = all(t in trained_profiles for t in required_types)
            if not has_all_required:
                missing = [t for t in required_types if t not in trained_profiles]
                logger.warning(f"Desktop login missing profiles: {missing}")
                return {
                    "can_skip_mfa": False,
                    "reason": "no_biometric_profile",
                    "trust_score": None,
                    "details": f"Missing profiles for desktop: {missing}"
                }
        elif device_category == "mobile":
            # Mobile needs ALL THREE: keystroke + touch + sensor
            required_types = ["KEYSTROKE", "TOUCH", "SENSOR_FUSION"]
            has_all_required = all(t in trained_profiles for t in required_types)
            if not has_all_required:
                missing = [t for t in required_types if t not in trained_profiles]
                logger.warning(f"Mobile login missing profiles: {missing}")
                return {
                    "can_skip_mfa": False,
                    "reason": "no_biometric_profile",
                    "trust_score": None,
                    "details": f"Missing profiles for mobile: {missing}"
                }

        # No analyzable data matched profiles
        if not scores:
            logger.warning("No analyzable biometric data matched trained profiles")
            return {
                "can_skip_mfa": False,
                "reason": "no_matching_biometric_type",
                "trust_score": None,
                "details": details
            }
        
        # Calculate combined trust score based on device type
        if device_category == "desktop":
            # Desktop: weight keystroke 70%, mouse 30%
            weights = {"KEYSTROKE": 0.7, "MOUSE": 0.3}
        else:
            # Mobile: weight all three equally-ish (keystroke most important)
            weights = {"KEYSTROKE": 0.5, "TOUCH": 0.3, "SENSOR_FUSION": 0.2}
        
        total_weight = sum(weights.get(t, 0.5) for t, _ in scores)
        combined_score = sum(weights.get(t, 0.5) * s for t, s in scores) / total_weight
        
        # Threshold for skipping MFA
        # Mobile has lower threshold due to higher variability in touch/sensor data
        threshold = 0.5 if device_category == "mobile" else 0.6
        
        logger.info(f"Combined trust score: {combined_score:.3f}, threshold: {threshold}, device: {device_category}, can_skip: {combined_score >= threshold}")
        
        return {
            "can_skip_mfa": combined_score >= threshold,
            "reason": "biometric_match" if combined_score >= threshold else "biometric_anomaly",
            "trust_score": round(combined_score, 3),
            "details": details,
            "individual_scores": {t: round(s, 3) for t, s in scores}
        }
    
    def _extract_keystroke_features(self, keystroke_data: List[Dict]) -> Optional[Dict]:
        if not keystroke_data or len(keystroke_data) < 3:
            return None
        
        import numpy as np
        
        # Calculate hold times and flight times
        hold_times = []
        flight_times = []
        timestamps = []
        
        for event in keystroke_data:
            if event.get("hold_time") and event["hold_time"] > 0:
                hold_times.append(event["hold_time"])
            if event.get("flight_time") and event["flight_time"] > 0:
                flight_times.append(event["flight_time"])
            if event.get("key_down_time"):
                timestamps.append(event["key_down_time"])
            elif event.get("timestamp"):
                timestamps.append(event["timestamp"])
        
        if not hold_times or len(hold_times) < 2:
            return None
        
        features = {
            # Hold time features (must match biometric_service!)
            "hold_time_mean": float(np.mean(hold_times)),
            "hold_time_std": float(np.std(hold_times)),
            "hold_time_median": float(np.median(hold_times)),
            "hold_time_min": float(np.min(hold_times)),
            "hold_time_max": float(np.max(hold_times)),
        }
        
        # Flight time features
        if flight_times and len(flight_times) >= 2:
            features["flight_time_mean"] = float(np.mean(flight_times))
            features["flight_time_std"] = float(np.std(flight_times))
            features["flight_time_median"] = float(np.median(flight_times))
            features["flight_time_min"] = float(np.min(flight_times))
            features["flight_time_max"] = float(np.max(flight_times))
        
        # Rhythm features
        if timestamps and len(timestamps) > 1:
            timestamps = sorted(timestamps)
            total_time = (timestamps[-1] - timestamps[0]) / 1000  # to seconds
            if total_time > 0:
                features["typing_speed"] = len(keystroke_data) / total_time
            
            # Inter-key intervals
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            intervals = [i for i in intervals if i > 0 and i < 2000]
            
            if intervals:
                pauses = sum(1 for i in intervals if i > 500)
                features["pause_rate"] = pauses / len(intervals)
                
                if np.mean(intervals) > 0:
                    features["rhythm_consistency"] = float(np.std(intervals) / np.mean(intervals))
        
        return features
    
    def _extract_mouse_features(self, mouse_data: List[Dict]) -> Optional[Dict]:
        if not mouse_data or len(mouse_data) < 5:
            return None
        
        import numpy as np
        
        features = {}
        
        # Get movement events with timestamps
        movements = []
        for d in mouse_data:
            if d.get("timestamp"):
                movements.append({
                    "x": d.get("x", 0),
                    "y": d.get("y", 0),
                    "t": d.get("timestamp", 0)
                })
        
        if len(movements) < 5:
            return None
        
        # Sort by timestamp
        movements = sorted(movements, key=lambda m: m["t"])
        
        # Calculate velocities
        velocities = []
        for i in range(1, len(movements)):
            dt = movements[i]["t"] - movements[i-1]["t"]
            if dt > 0:
                dx = movements[i]["x"] - movements[i-1]["x"]
                dy = movements[i]["y"] - movements[i-1]["y"]
                dist = np.sqrt(dx**2 + dy**2)
                velocities.append(dist / dt)
        
        if velocities:
            features["velocity_mean"] = float(np.mean(velocities))
            features["velocity_std"] = float(np.std(velocities)) if len(velocities) > 1 else 0.0
            features["velocity_median"] = float(np.median(velocities))
            features["velocity_max"] = float(np.max(velocities))
        
        # Calculate accelerations
        accelerations = []
        for i in range(1, len(velocities)):
            if i < len(movements) - 1:
                dt = movements[i+1]["t"] - movements[i]["t"]
                if dt > 0:
                    accelerations.append((velocities[i] - velocities[i-1]) / dt)
        
        if accelerations:
            features["acceleration_mean"] = float(np.mean(np.abs(accelerations)))
            features["acceleration_std"] = float(np.std(accelerations)) if len(accelerations) > 1 else 0.0
            features["acceleration_max"] = float(np.max(np.abs(accelerations)))
        
        # Calculate jerk
        jerks = []
        for i in range(1, len(accelerations)):
            if i + 2 < len(movements):
                dt = movements[i+2]["t"] - movements[i+1]["t"]
                if dt > 0:
                    jerks.append((accelerations[i] - accelerations[i-1]) / dt)
        
        if jerks:
            features["jerk_mean"] = float(np.mean(np.abs(jerks)))
            features["jerk_std"] = float(np.std(jerks)) if len(jerks) > 1 else 0.0
        
        # Direction changes
        direction_changes = 0
        for i in range(2, len(movements)):
            v1 = (movements[i-1]["x"] - movements[i-2]["x"], movements[i-1]["y"] - movements[i-2]["y"])
            v2 = (movements[i]["x"] - movements[i-1]["x"], movements[i]["y"] - movements[i-1]["y"])
            
            len1 = np.sqrt(v1[0]**2 + v1[1]**2)
            len2 = np.sqrt(v2[0]**2 + v2[1]**2)
            
            if len1 > 1 and len2 > 1:
                cos_angle = (v1[0]*v2[0] + v1[1]*v2[1]) / (len1 * len2)
                cos_angle = np.clip(cos_angle, -1, 1)
                angle = np.arccos(cos_angle)
                if angle > 0.5:
                    direction_changes += 1
        
        features["direction_changes"] = direction_changes / len(movements) if movements else 0
        
        # Straightness index
        if len(movements) > 1:
            direct_dist = np.sqrt(
                (movements[-1]["x"] - movements[0]["x"])**2 + 
                (movements[-1]["y"] - movements[0]["y"])**2
            )
            path_length = sum(
                np.sqrt(
                    (movements[i]["x"] - movements[i-1]["x"])**2 + 
                    (movements[i]["y"] - movements[i-1]["y"])**2
                )
                for i in range(1, len(movements))
            )
            if path_length > 0:
                features["straightness_index"] = direct_dist / path_length
                features["movement_efficiency"] = direct_dist / path_length
        
        # Pause frequency
        if velocities:
            pauses = sum(1 for v in velocities if v < 0.01)
            features["pause_frequency"] = pauses / len(velocities)
        
        return features
    
    def _extract_touch_features(self, touch_data: List[Dict]) -> Optional[Dict]:
        if not touch_data or len(touch_data) < 3:
            return None
        
        import numpy as np
        
        features = {}
        
        # Get touch events with timestamps
        touches = []
        for d in touch_data:
            if d.get("timestamp"):
                touches.append({
                    "x": d.get("x", 0),
                    "y": d.get("y", 0),
                    "t": d.get("timestamp", 0),
                    "pressure": d.get("pressure"),
                    "event_type": d.get("event_type", "")
                })
        
        if len(touches) < 3:
            return None
        
        # Sort by timestamp
        touches = sorted(touches, key=lambda t: t["t"])
        
        # Calculate tap velocities (similar to mouse but for touch)
        velocities = []
        for i in range(1, len(touches)):
            dt = touches[i]["t"] - touches[i-1]["t"]
            if dt > 0:
                dx = touches[i]["x"] - touches[i-1]["x"]
                dy = touches[i]["y"] - touches[i-1]["y"]
                dist = np.sqrt(dx**2 + dy**2)
                velocities.append(dist / dt)
        
        if velocities:
            features["velocity_mean"] = float(np.mean(velocities))
            features["velocity_std"] = float(np.std(velocities)) if len(velocities) > 1 else 0.0
            features["velocity_max"] = float(np.max(velocities))
        
        # Pressure features (if available)
        pressures = [t["pressure"] for t in touches if t.get("pressure") is not None]
        if pressures:
            features["pressure_mean"] = float(np.mean(pressures))
            features["pressure_std"] = float(np.std(pressures)) if len(pressures) > 1 else 0.0
        
        # Tap timing (interval between taps)
        tap_starts = [t["t"] for t in touches if t.get("event_type") == "start"]
        if len(tap_starts) > 1:
            intervals = [tap_starts[i+1] - tap_starts[i] for i in range(len(tap_starts)-1)]
            if intervals:
                features["tap_interval_mean"] = float(np.mean(intervals))
                features["tap_interval_std"] = float(np.std(intervals)) if len(intervals) > 1 else 0.0
        
        return features
    
    async def verify_mfa(
        self, 
        mfa_token: str, 
        code: str,
        ip_address: str = None,
        user_agent: str = None
    ) -> User:
        # Get user ID from pending MFA
        user_id = await self.redis.client.get(f"mfa_pending:{mfa_token}")
        if not user_id:
            raise ValueError("Invalid or expired MFA token")
        
        result = await self.db.execute(
            select(User).where(User.id == UUID(user_id))
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("User not found")
        
        # Try TOTP first
        if len(code) == 6 and code.isdigit():
            if verify_totp(user.totp_secret, code):
                await self.redis.client.delete(f"mfa_pending:{mfa_token}")
                await self._log_event(
                    user.id,
                    EventType.MFA_SUCCESS,
                    {"method": "totp"},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return user
        
        # Try backup code
        if user.backup_codes:
            is_valid, index = verify_backup_code(code, user.backup_codes)
            if is_valid:
                # Remove used backup code
                user.backup_codes = [c for i, c in enumerate(user.backup_codes) if i != index]
                await self.redis.client.delete(f"mfa_pending:{mfa_token}")
                await self._log_event(
                    user.id,
                    EventType.MFA_SUCCESS,
                    {"method": "backup_code"},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return user
        
        await self._log_event(
            user.id,
            EventType.MFA_FAILED,
            {"reason": "invalid_code"},
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise ValueError("Invalid MFA code")
    
    async def create_session(
        self,
        user: User,
        mfa_verified: bool = False,
        ip_address: str = None,
        user_agent: str = None,
        device_fingerprint: str = None,
        initial_trust_score: float = 1.0
    ) -> Session:
        """Create a new session for authenticated user."""
        session = Session(
            user_id=user.id,
            session_token=generate_session_token(),
            mfa_verified=mfa_verified,
            trust_score=initial_trust_score,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            expires_at=datetime.utcnow() + timedelta(minutes=settings.session_timeout_minutes)
        )
        
        self.db.add(session)
        await self.db.flush()
        
        # Cache session in Redis
        await self.redis.set_session(
            str(session.id),
            {
                "user_id": str(user.id),
                "token": session.session_token,
                "mfa_verified": mfa_verified,
                "trust_score": initial_trust_score
            },
            ttl=settings.session_timeout_minutes * 60
        )
        
        return session
    
    async def setup_totp(self, user: User) -> Tuple[str, str, list]:
        secret = generate_totp_secret()
        qr_code = generate_totp_qr_code(secret, user.username)
        backup_codes = generate_backup_codes()
        
        # Store temporarily until confirmed
        await self.redis.client.setex(
            f"totp_setup:{user.id}",
            600,  # 10 minutes
            secret
        )
        
        return secret, qr_code, backup_codes
    
    async def confirm_totp_setup(self, user: User, code: str, backup_codes: list) -> bool:
        secret = await self.redis.client.get(f"totp_setup:{user.id}")
        if not secret:
            raise ValueError("TOTP setup expired. Please start again.")
        
        if not verify_totp(secret, code):
            raise ValueError("Invalid verification code")
        
        # Enable TOTP
        user.totp_secret = secret
        user.totp_enabled = True
        user.backup_codes = hash_backup_codes(backup_codes)
        
        await self.redis.client.delete(f"totp_setup:{user.id}")
        
        return True
    
    async def disable_totp(self, user: User, password: str) -> bool:
        if not verify_password(password, user.password_hash):
            raise ValueError("Invalid password")
        
        user.totp_secret = None
        user.totp_enabled = False
        user.backup_codes = None
        
        return True
    
    async def request_password_reset(self, email: str) -> Optional[str]:
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            return None  # Don't reveal if email exists
        
        token = generate_verification_token()
        user.password_reset_token = token
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        
        # Send password reset email
        await email_service.send_password_reset(
            user.email,
            user.username,
            token
        )
        
        await self._log_event(user.id, EventType.PASSWORD_RESET_REQUESTED)
        
        return token
    
    async def reset_password(self, token: str, new_password: str) -> bool:
        result = await self.db.execute(
            select(User).where(
                User.password_reset_token == token,
                User.password_reset_expires > datetime.utcnow()
            )
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("Invalid or expired reset token")
        
        user.password_hash = get_password_hash(new_password)
        user.password_reset_token = None
        user.password_reset_expires = None
        user.failed_login_attempts = 0
        user.locked_until = None
        
        await self._log_event(user.id, EventType.PASSWORD_RESET_COMPLETED)
        
        return True
    
    async def verify_email(self, token: str) -> bool:
        result = await self.db.execute(
            select(User).where(
                User.email_verification_token == token,
                User.email_verification_expires > datetime.utcnow()
            )
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise ValueError("Invalid or expired verification token")
        
        user.is_verified = True
        user.email_verification_token = None
        user.email_verification_expires = None
        
        await self._log_event(user.id, EventType.EMAIL_VERIFIED)
        
        return True
    
    async def logout(self, session_id: UUID) -> bool:
        result = await self.db.execute(
            select(Session).where(Session.id == session_id)
        )
        session = result.scalar_one_or_none()
        
        if session:
            session.is_active = False
            await self.redis.delete_session(str(session_id))
            await self._log_event(session.user_id, EventType.LOGOUT, session_id=session_id)
        
        return True
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_session_token(self, token: str) -> Optional[Tuple[User, Session]]:
        result = await self.db.execute(
            select(Session)
            .options(selectinload(Session.user))
            .where(
                Session.session_token == token,
                Session.is_active == True,
                Session.expires_at > datetime.utcnow()
            )
        )
        session = result.scalar_one_or_none()
        
        if session:
            # Update last activity
            session.last_activity = datetime.utcnow()
            await self.redis.extend_session(str(session.id))
            return session.user, session
        
        return None, None
    
    async def _handle_failed_login(
        self, 
        user: User, 
        ip_address: str = None,
        user_agent: str = None
    ):
        user.failed_login_attempts += 1
        
        if user.failed_login_attempts >= settings.max_failed_login_attempts:
            user.locked_until = datetime.utcnow() + timedelta(
                minutes=settings.account_lockout_minutes
            )
            await self._log_event(
                user.id, 
                EventType.ACCOUNT_LOCKED,
                {"attempts": user.failed_login_attempts},
                ip_address=ip_address,
                user_agent=user_agent
            )
        else:
            await self._log_event(
                user.id,
                EventType.LOGIN_FAILED,
                {"attempts": user.failed_login_attempts},
                ip_address=ip_address,
                user_agent=user_agent
            )
    
    async def _log_event(
        self,
        user_id: UUID,
        event_type: EventType,
        details: dict = None,
        session_id: UUID = None,
        ip_address: str = None,
        user_agent: str = None
    ):
        event = SecurityEvent(
            user_id=user_id,
            session_id=session_id,
            event_type=event_type,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.db.add(event)
