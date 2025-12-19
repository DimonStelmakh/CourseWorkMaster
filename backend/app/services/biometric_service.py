from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from uuid import UUID
import numpy as np
import json
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models import (
    User, Session, BiometricData, BiometricProfile, 
    TrustScoreHistory, SecurityEvent, BiometricType, EventType
)
from app.core.config import settings
from app.core.redis import RedisClient
from app.schemas import BiometricAnalysisResult
from app.services.email_service import email_service
from app.ml.models import BiometricMLModel, BiometricModelManager

logger = logging.getLogger(__name__)


class BiometricAnalyzer:
    def __init__(self, db: AsyncSession, redis: RedisClient):
        self.db = db
        self.redis = redis
        self._model_managers: Dict[str, BiometricModelManager] = {}
    
    async def collect_biometric_data(
        self,
        user_id: UUID,
        session_id: UUID,
        data_type: BiometricType,
        raw_data: List[Dict[str, Any]],
        device_category: str = 'desktop'
    ) -> BiometricData:
        """Collect and store biometric data with device category."""
        # Extract features from raw data
        features = self._extract_features(data_type, raw_data)
        
        data_type_str = data_type.value if hasattr(data_type, 'value') else str(data_type)
        
        # Store in database with device_category
        biometric_data = BiometricData(
            user_id=user_id,
            session_id=session_id,
            data_type=data_type_str,
            device_category=device_category,
            raw_data=raw_data,
            features=features
        )
        
        self.db.add(biometric_data)
        await self.db.flush()
        
        # Buffer data in Redis for real-time analysis
        # Use session_id to keep data separate between different devices/sessions
        await self.redis.append_biometric_buffer(
            str(session_id),
            f"{data_type_str}_{device_category}",
            {"features": features, "timestamp": datetime.utcnow().isoformat()}
        )
        
        # Check if we should auto-train the model (per device category)
        await self._check_auto_train(user_id, data_type_str, device_category)
        
        return biometric_data
    
    async def _check_auto_train(self, user_id: UUID, data_type: str, device_category: str = 'desktop'):
        """Check if we have enough data to auto-train the model for specific device type."""
        # Count samples for this device category
        count_result = await self.db.execute(
            select(func.count(BiometricData.id)).where(
                BiometricData.user_id == user_id,
                BiometricData.data_type == data_type,
                BiometricData.device_category == device_category
            )
        )
        count = count_result.scalar() or 0
        
        # Check if profile exists and is trained for this device
        profile_result = await self.db.execute(
            select(BiometricProfile).where(
                BiometricProfile.user_id == user_id,
                BiometricProfile.data_type == data_type,
                BiometricProfile.device_category == device_category
            )
        )
        profile = profile_result.scalar_one_or_none()
        
        # Auto-train if we have enough samples and model not trained yet
        # Or retrain if we have significantly more samples (2x)
        should_train = False
        
        if count >= settings.min_training_samples:
            if not profile:
                should_train = True
            elif not profile.profile_data or not profile.profile_data.get("ml_trained"):
                should_train = True
            elif profile.sample_count > 0 and count >= profile.sample_count * 2:
                # Retrain with more data
                should_train = True
                logger.info(f"Retraining model for user {user_id}, type {data_type}/{device_category} with {count} samples")
        
        if should_train:
            # Create a fake BiometricType for update_profile
            from app.schemas import BiometricType as BT
            try:
                bt = BT(data_type)
                result = await self.update_profile(user_id, bt, device_category)
                if result:
                    logger.info(f"Auto-trained {data_type}/{device_category} model for user {user_id}")
                else:
                    logger.warning(f"Auto-train for {data_type}/{device_category} returned None - not enough valid features")
            except Exception as e:
                logger.error(f"Auto-train failed: {e}", exc_info=True)
    
    async def analyze_behavior(
        self,
        user_id: UUID,
        session_id: UUID,
        data_type: BiometricType = None,
        device_category: str = None
    ) -> BiometricAnalysisResult:
        """
        Analyze user behavior and calculate trust score using ML models.
        Adapts to available biometric types (desktop vs mobile).
        Uses session-based buffer to avoid mixing data from different devices.
        """
        # Get or create model manager for this user
        model_manager = await self._get_model_manager(user_id)
        
        scores = {}
        anomaly_details = {}
        available_types = []
        new_device_type = False
        detected_device_category = None
        
        # Try both device categories if not specified
        device_cats = [device_category] if device_category else ['desktop', 'mobile']
        
        # Define which types to check per device
        desktop_types = ["KEYSTROKE", "MOUSE"]
        mobile_types = ["KEYSTROKE", "TOUCH", "SENSOR_FUSION"]
        
        for dev_cat in device_cats:
            bio_types = desktop_types if dev_cat == 'desktop' else mobile_types
            
            for bio_type in bio_types:
                if data_type and bio_type != (data_type.value if hasattr(data_type, 'value') else str(data_type)):
                    continue
                
                # Get recent biometric data from buffer (session-based)
                buffer_key = f"{bio_type}_{dev_cat}"
                buffer_data = await self.redis.get_biometric_buffer(
                    str(session_id),  # Use session_id, not user_id!
                    buffer_key
                )
                
                if not buffer_data:
                    continue
                
                # Found data for this device category
                if detected_device_category is None:
                    detected_device_category = dev_cat
                
                available_types.append(f"{bio_type}_{dev_cat}")
                
                # Aggregate features from buffer
                features_list = [item.get("features", {}) for item in buffer_data if item.get("features")]
                if not features_list:
                    continue
                
                # Average features from recent samples
                aggregated_features = self._aggregate_features(features_list)
                
                # Check if we have a trained model for this type+device
                model_key = f"{bio_type}_{dev_cat}"
                model = model_manager.models.get(model_key)
                has_trained_model = model and model.is_trained
                
                if has_trained_model:
                    # Get prediction from ML model
                    trust, details = model_manager.predict(model_key, aggregated_features)
                    scores[model_key] = trust
                    
                    if details.get("status") == "analyzed" and details.get("anomalous_features"):
                        anomaly_details[model_key] = {
                            "trust": trust,
                            "ocsvm": details.get("ocsvm_prediction"),
                            "iforest": details.get("iforest_prediction"),
                            "anomalous_features": details.get("anomalous_features")
                        }
                else:
                    # No trained model - this might be a new device type
                    # Check if user has ANY trained models
                    user_has_models = any(m.is_trained for m in model_manager.models.values())
                    
                    if user_has_models:
                        # User has profile but not for this biometric type
                        new_device_type = True
                        logger.info(f"New device type detected for user {user_id}: {model_key}")
                    
                    # Give neutral score for untrained types
                    scores[model_key] = 1.0
        
        # Determine device category from available types
        device_category = self._determine_device_category(available_types)
        
        # Calculate combined trust score (only from types we have data for)
        trust_score = self._calculate_combined_score(scores)
        
        # Determine if MFA should be required
        # 1. Low trust score (anomaly detected)
        # 2. New device type (no trained model for current device's biometrics)
        anomaly_detected = trust_score < settings.trust_score_threshold
        requires_mfa = anomaly_detected or new_device_type
        
        # Store trust score history
        await self._store_trust_score(
            session_id=session_id,
            user_id=user_id,
            score=trust_score,
            scores=scores,
            anomaly_details=anomaly_details if anomaly_detected else None
        )
        
        # Cache current trust score
        await self.redis.set_trust_score(str(session_id), trust_score)
        
        # Update session trust score
        await self._update_session_trust_score(session_id, trust_score)
        
        # Log events
        if anomaly_detected:
            await self._log_anomaly_event(user_id, session_id, trust_score, anomaly_details)
        
        if new_device_type:
            await self._log_new_device_event(user_id, session_id, device_category, available_types)
        
        # Build detailed result
        result_details = anomaly_details if anomaly_detected else None
        if new_device_type:
            result_details = result_details or {}
            result_details["new_device_type"] = {
                "detected": True,
                "device_category": device_category,
                "available_types": available_types,
                "message": "First login from this device type. MFA required to build profile."
            }
        
        # Extract scores by base type for result (take best score for each type)
        keystroke_score = scores.get("KEYSTROKE_desktop") or scores.get("KEYSTROKE_mobile")
        mouse_score = scores.get("MOUSE_desktop")
        touch_score = scores.get("TOUCH_mobile")
        sensor_score = scores.get("SENSOR_FUSION_mobile")
        
        return BiometricAnalysisResult(
            trust_score=trust_score,
            keystroke_score=keystroke_score,
            mouse_score=mouse_score,
            touch_score=touch_score,
            sensor_score=sensor_score,
            anomaly_detected=anomaly_detected,
            anomaly_details=result_details,
            requires_mfa=requires_mfa
        )
    
    def _determine_device_category(self, available_types: List[str]) -> str:
        """Determine device category based on available biometric types."""
        # Now types have suffixes like KEYSTROKE_desktop, MOUSE_desktop, TOUCH_mobile
        has_desktop = any('_desktop' in t for t in available_types)
        has_mobile = any('_mobile' in t for t in available_types)
        
        if has_desktop and has_mobile:
            return "hybrid"  # Tablet with keyboard or touchscreen laptop
        elif has_mobile:
            return "mobile"
        elif has_desktop:
            return "desktop"
        else:
            return "unknown"
    
    async def _log_new_device_event(
        self, 
        user_id: UUID, 
        session_id: UUID, 
        device_category: str,
        available_types: List[str]
    ):
        """Log event when user logs in from new device type."""
        event = SecurityEvent(
            user_id=user_id,
            session_id=session_id,
            event_type="NEW_DEVICE_TYPE",
            details={
                "device_category": device_category,
                "biometric_types": available_types,
                "message": "First login from this device category"
            }
        )
        self.db.add(event)
    
    def _aggregate_features(self, features_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate multiple feature samples into one by averaging."""
        if not features_list:
            return {}
        
        if len(features_list) == 1:
            return features_list[0]
        
        aggregated = {}
        all_keys = set()
        for f in features_list:
            all_keys.update(f.keys())
        
        for key in all_keys:
            values = [f.get(key) for f in features_list if f.get(key) is not None]
            if values:
                if isinstance(values[0], (int, float)):
                    aggregated[key] = float(np.mean(values))
                else:
                    aggregated[key] = values[-1]  # Use latest for non-numeric
        
        return aggregated
    
    async def _get_model_manager(self, user_id: UUID) -> BiometricModelManager:
        """Get or create model manager for user, loading from DB if available."""
        user_id_str = str(user_id)
        
        if user_id_str not in self._model_managers:
            manager = BiometricModelManager()
            
            # Load trained models from database
            result = await self.db.execute(
                select(BiometricProfile).where(BiometricProfile.user_id == user_id)
            )
            profiles = result.scalars().all()
            
            for profile in profiles:
                if profile.profile_data and profile.profile_data.get("ml_model"):
                    try:
                        # Build model key with device_category
                        device_cat = profile.device_category or 'desktop'
                        model_key = f"{profile.data_type}_{device_cat}"
                        
                        manager.load_model(
                            model_key,
                            profile.profile_data["ml_model"]
                        )
                        logger.info(f"Loaded ML model for user {user_id}, type {model_key}")
                    except Exception as e:
                        logger.error(f"Error loading ML model: {e}")
            
            self._model_managers[user_id_str] = manager
        
        return self._model_managers[user_id_str]
    
    async def update_profile(
        self,
        user_id: UUID,
        data_type: BiometricType,
        device_category: str = 'desktop'
    ) -> BiometricProfile:
        """
        Update user's biometric profile and train ML model for specific device category.
        Should be called periodically or after sufficient samples.
        """
        data_type_str = data_type.value if hasattr(data_type, 'value') else str(data_type)
        
        # Get all data for this user, type, and device category
        result = await self.db.execute(
            select(BiometricData).where(
                BiometricData.user_id == user_id,
                BiometricData.data_type == data_type_str,
                BiometricData.device_category == device_category
            ).order_by(BiometricData.timestamp.desc()).limit(100)
        )
        all_data = result.scalars().all()
        
        if len(all_data) < settings.min_training_samples:
            logger.info(f"Not enough samples for {data_type_str}/{device_category}: {len(all_data)}/{settings.min_training_samples}")
            return None
        
        # Extract features - filter out empty ones
        features_list = []
        for data in all_data:
            if data.features and len(data.features) > 0:
                # Check that features have actual values, not just empty dict
                has_values = any(v is not None and v != 0 for v in data.features.values())
                if has_values:
                    features_list.append(data.features)
                    # Mark as training data
                    data.is_training_data = True
        
        if len(features_list) < settings.min_training_samples:
            logger.info(f"Not enough valid features for training {data_type_str}/{device_category}: {len(features_list)}/{settings.min_training_samples}")
            return None
        
        # Use unique model key for device category
        model_key = f"{data_type_str}_{device_category}"
        logger.info(f"Training model with {len(features_list)} feature samples for {model_key}")
        
        # Train ML model
        model_manager = await self._get_model_manager(user_id)
        ml_trained = model_manager.train_model(model_key, features_list)
        
        # Calculate profile statistics for reference
        profile_data = self._calculate_profile_statistics(data_type_str, features_list)
        profile_data["device_category"] = device_category
        
        # Include serialized ML model in profile
        if ml_trained:
            model = model_manager.models.get(model_key)
            if model:
                profile_data["ml_model"] = model.serialize()
                profile_data["ml_trained"] = True
                profile_data["ml_samples"] = model.training_samples_count
                logger.info(f"ML model trained successfully for user {user_id}, {model_key}")
        else:
            logger.warning(f"ML training returned False for {model_key}")
        
        # Update or create profile for this device category
        result = await self.db.execute(
            select(BiometricProfile).where(
                BiometricProfile.user_id == user_id,
                BiometricProfile.data_type == data_type_str,
                BiometricProfile.device_category == device_category
            )
        )
        profile = result.scalar_one_or_none()
        
        if profile:
            profile.profile_data = profile_data
            profile.sample_count = len(features_list)
            profile.last_updated = datetime.utcnow()
            profile.model_version = "2.0-ml" if ml_trained else "1.0"
        else:
            profile = BiometricProfile(
                user_id=user_id,
                data_type=data_type_str,
                device_category=device_category,
                profile_data=profile_data,
                sample_count=len(features_list),
                model_version="2.0-ml" if ml_trained else "1.0"
            )
            self.db.add(profile)
        
        await self.db.flush()
        return profile
    
    async def get_profile_status(self, user_id: UUID) -> Dict[str, Any]:
        """Get status of user's biometric profiles including ML training status and device readiness."""
        result = await self.db.execute(
            select(BiometricProfile).where(BiometricProfile.user_id == user_id)
        )
        profiles = result.scalars().all()
        
        logger.info(f"=== GET PROFILE STATUS for user {user_id} ===")
        logger.info(f"Found {len(profiles)} profiles in DB")
        for p in profiles:
            logger.info(f"  Profile: {p.data_type}, device_cat={p.device_category}, trained={p.profile_data.get('ml_trained') if p.profile_data else None}")
        
        # Count samples per type AND device_category
        sample_counts = {}
        bio_types = ["KEYSTROKE", "MOUSE", "TOUCH", "SENSOR_FUSION"]
        device_categories = ["desktop", "mobile"]
        
        for bio_type in bio_types:
            sample_counts[bio_type] = {}
            for device_cat in device_categories:
                # Count records where device_category matches OR is NULL (treat NULL as desktop)
                if device_cat == "desktop":
                    count_result = await self.db.execute(
                        select(func.count(BiometricData.id)).where(
                            BiometricData.user_id == user_id,
                            BiometricData.data_type == bio_type,
                            (BiometricData.device_category == device_cat) | 
                            (BiometricData.device_category.is_(None))
                        )
                    )
                else:
                    count_result = await self.db.execute(
                        select(func.count(BiometricData.id)).where(
                            BiometricData.user_id == user_id,
                            BiometricData.data_type == bio_type,
                            BiometricData.device_category == device_cat
                        )
                    )
                sample_counts[bio_type][device_cat] = count_result.scalar() or 0
        
        logger.info(f"Sample counts: {sample_counts}")
        
        # Build ML status from profiles
        ml_status = {}
        for p in profiles:
            device_cat = p.device_category or 'desktop'
            key = f"{p.data_type}_{device_cat}"
            if p.profile_data:
                ml_status[key] = {
                    "data_type": p.data_type,
                    "device_category": device_cat,
                    "trained": p.profile_data.get("ml_trained", False),
                    "samples": p.profile_data.get("ml_samples", p.sample_count),
                    "model_version": p.model_version
                }
        
        logger.info(f"ML status keys: {list(ml_status.keys())}")
        
        # Calculate device-specific readiness
        desktop_types = ["KEYSTROKE", "MOUSE"]
        mobile_types = ["KEYSTROKE", "TOUCH", "SENSOR_FUSION"]  # Mobile also has keystroke!
        
        # Desktop status
        desktop_keystroke_samples = sample_counts.get("KEYSTROKE", {}).get("desktop", 0)
        desktop_mouse_samples = sample_counts.get("MOUSE", {}).get("desktop", 0)
        desktop_keystroke_trained = ml_status.get("KEYSTROKE_desktop", {}).get("trained", False)
        desktop_mouse_trained = ml_status.get("MOUSE_desktop", {}).get("trained", False)
        
        # Mobile status
        mobile_keystroke_samples = sample_counts.get("KEYSTROKE", {}).get("mobile", 0)
        mobile_touch_samples = sample_counts.get("TOUCH", {}).get("mobile", 0)
        mobile_sensor_samples = sample_counts.get("SENSOR_FUSION", {}).get("mobile", 0)
        mobile_keystroke_trained = ml_status.get("KEYSTROKE_mobile", {}).get("trained", False)
        mobile_touch_trained = ml_status.get("TOUCH_mobile", {}).get("trained", False)
        mobile_sensor_trained = ml_status.get("SENSOR_FUSION_mobile", {}).get("trained", False)
        
        # Desktop ready = both KEYSTROKE and MOUSE trained
        desktop_ready = desktop_keystroke_trained and desktop_mouse_trained
        # Mobile ready = ALL THREE trained: keystroke + touch + sensor
        mobile_ready = mobile_keystroke_trained and mobile_touch_trained and mobile_sensor_trained
        
        return {
            "sample_counts": {
                "KEYSTROKE": desktop_keystroke_samples + mobile_keystroke_samples,
                "MOUSE": desktop_mouse_samples,
                "TOUCH": mobile_touch_samples,
                "SENSOR_FUSION": mobile_sensor_samples,
            },
            "sample_counts_by_device": sample_counts,
            "ml_status": ml_status,
            "min_required": settings.min_training_samples,
            
            # Device-specific status for UI
            "device_status": {
                "desktop": {
                    "keystroke_samples": desktop_keystroke_samples,
                    "mouse_samples": desktop_mouse_samples,
                    "keystroke_trained": desktop_keystroke_trained,
                    "mouse_trained": desktop_mouse_trained,
                    "trained": desktop_ready,
                    "ready": desktop_keystroke_samples >= settings.min_training_samples and 
                             desktop_mouse_samples >= settings.min_training_samples
                },
                "mobile": {
                    "keystroke_samples": mobile_keystroke_samples,
                    "touch_samples": mobile_touch_samples,
                    "sensor_samples": mobile_sensor_samples,
                    "keystroke_trained": mobile_keystroke_trained,
                    "touch_trained": mobile_touch_trained,
                    "sensor_trained": mobile_sensor_trained,
                    "trained": mobile_ready,
                    "ready": mobile_keystroke_samples >= settings.min_training_samples and
                             mobile_touch_samples >= settings.min_training_samples and 
                             mobile_sensor_samples >= settings.min_training_samples
                }
            },
            
            # Overall status
            "profile_ready": desktop_ready or mobile_ready,
            "ml_ready": desktop_ready or mobile_ready
        }
    
    def _extract_features(
        self, 
        data_type, 
        raw_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Extract statistical features from raw biometric data."""
        data_type_str = data_type.value if hasattr(data_type, 'value') else str(data_type)
        
        if data_type_str == "KEYSTROKE":
            return self._extract_keystroke_features(raw_data)
        elif data_type_str == "MOUSE":
            return self._extract_mouse_features(raw_data)
        elif data_type_str == "TOUCH":
            return self._extract_touch_features(raw_data)
        elif data_type_str == "SENSOR_FUSION":
            return self._extract_sensor_features(raw_data)
        
        return {}
    
    def _extract_keystroke_features(self, data: List[Dict]) -> Dict[str, Any]:
        """
        Extract keystroke dynamics features.
        Focus on TEMPORAL patterns - these are most discriminative for user identification.
        """
        if not data or len(data) < 2:
            return {}
        
        hold_times = [d.get("hold_time", 0) for d in data if d.get("hold_time") and d.get("hold_time") > 0]
        flight_times = [d.get("flight_time", 0) for d in data if d.get("flight_time") and d.get("flight_time") > 0]
        
        features = {}
        
        # Hold time features (how long each key is pressed)
        if hold_times:
            features["hold_time_mean"] = float(np.mean(hold_times))
            features["hold_time_std"] = float(np.std(hold_times)) if len(hold_times) > 1 else 0.0
            features["hold_time_median"] = float(np.median(hold_times))
            features["hold_time_min"] = float(np.min(hold_times))
            features["hold_time_max"] = float(np.max(hold_times))
        
        # Flight time features (time between key releases and next key presses)
        if flight_times:
            features["flight_time_mean"] = float(np.mean(flight_times))
            features["flight_time_std"] = float(np.std(flight_times)) if len(flight_times) > 1 else 0.0
            features["flight_time_median"] = float(np.median(flight_times))
            features["flight_time_min"] = float(np.min(flight_times))
            features["flight_time_max"] = float(np.max(flight_times))
        
        # Typing rhythm analysis
        timestamps = []
        for d in data:
            if d.get("key_down_time"):
                timestamps.append(d["key_down_time"])
            elif d.get("timestamp"):
                timestamps.append(d["timestamp"])
        
        if len(timestamps) > 1:
            # Sort timestamps to ensure proper order
            timestamps = sorted(timestamps)
            
            # Typing speed (characters per second)
            total_time = (timestamps[-1] - timestamps[0]) / 1000  # Convert to seconds
            if total_time > 0:
                features["typing_speed"] = len(data) / total_time
            
            # Inter-key intervals
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            intervals = [i for i in intervals if i > 0 and i < 2000]  # Filter outliers (< 2 seconds)
            
            if intervals:
                # Pause rate - how often user pauses (interval > 500ms)
                pauses = sum(1 for i in intervals if i > 500)
                features["pause_rate"] = pauses / len(intervals)
                
                # Rhythm consistency - coefficient of variation of intervals
                if np.mean(intervals) > 0:
                    features["rhythm_consistency"] = float(np.std(intervals) / np.mean(intervals))
        
        return features
    
    def _extract_mouse_features(self, data: List[Dict]) -> Dict[str, Any]:
        """
        Extract mouse dynamics features.
        Focus on MOVEMENT PATTERNS - velocity, acceleration, jerk.
        Coordinates are NOT useful for identification!
        """
        if not data or len(data) < 3:
            return {}
        
        features = {}
        
        # Get movement events with timestamps
        movements = []
        for d in data:
            if d.get("event_type") == "move" and d.get("timestamp"):
                movements.append({
                    "x": d.get("x", 0),
                    "y": d.get("y", 0),
                    "t": d.get("timestamp", 0)
                })
        
        if len(movements) < 3:
            return {}
        
        # Sort by timestamp
        movements = sorted(movements, key=lambda m: m["t"])
        
        # Calculate velocities (pixels per ms)
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
        
        # Calculate accelerations (change in velocity)
        accelerations = []
        for i in range(1, len(velocities)):
            dt = movements[i+1]["t"] - movements[i]["t"]
            if dt > 0:
                accelerations.append((velocities[i] - velocities[i-1]) / dt)
        
        if accelerations:
            features["acceleration_mean"] = float(np.mean(np.abs(accelerations)))
            features["acceleration_std"] = float(np.std(accelerations)) if len(accelerations) > 1 else 0.0
            features["acceleration_max"] = float(np.max(np.abs(accelerations)))
        
        # Calculate jerk (change in acceleration) - important for smoothness
        jerks = []
        for i in range(1, len(accelerations)):
            dt = movements[i+2]["t"] - movements[i+1]["t"]
            if dt > 0:
                jerks.append((accelerations[i] - accelerations[i-1]) / dt)
        
        if jerks:
            features["jerk_mean"] = float(np.mean(np.abs(jerks)))
            features["jerk_std"] = float(np.std(jerks)) if len(jerks) > 1 else 0.0
        
        # Direction changes - how often user changes direction
        direction_changes = 0
        for i in range(2, len(movements)):
            v1 = (movements[i-1]["x"] - movements[i-2]["x"], movements[i-1]["y"] - movements[i-2]["y"])
            v2 = (movements[i]["x"] - movements[i-1]["x"], movements[i]["y"] - movements[i-1]["y"])
            
            len1 = np.sqrt(v1[0]**2 + v1[1]**2)
            len2 = np.sqrt(v2[0]**2 + v2[1]**2)
            
            if len1 > 1 and len2 > 1:  # Minimum movement threshold
                cos_angle = (v1[0]*v2[0] + v1[1]*v2[1]) / (len1 * len2)
                cos_angle = np.clip(cos_angle, -1, 1)
                angle = np.arccos(cos_angle)
                if angle > 0.5:  # ~30 degrees
                    direction_changes += 1
        
        features["direction_changes"] = direction_changes / len(movements) if movements else 0
        
        # Straightness index - ratio of direct distance to actual path length
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
        
        # Pause frequency - periods with very low velocity
        if velocities:
            pauses = sum(1 for v in velocities if v < 0.01)
            features["pause_frequency"] = pauses / len(velocities)
        
        return features
        
        # Click patterns
        clicks = [d for d in data if d.get("event_type") == "click"]
        if clicks:
            features["click_count"] = len(clicks)
        
        return features
    
    def _extract_touch_features(self, data: List[Dict]) -> Dict[str, Any]:
        """Extract touch dynamics features."""
        if not data:
            return {}
        
        pressures = [d.get("pressure", 0) for d in data if d.get("pressure")]
        areas = [d.get("touch_area", 0) for d in data if d.get("touch_area")]
        velocities = [d.get("velocity", 0) for d in data if d.get("velocity")]
        
        features = {}
        
        if pressures:
            features["pressure_mean"] = float(np.mean(pressures))
            features["pressure_std"] = float(np.std(pressures))
        
        if areas:
            features["touch_area_mean"] = float(np.mean(areas))
            features["touch_area_std"] = float(np.std(areas))
        
        if velocities:
            features["swipe_velocity_mean"] = float(np.mean(velocities))
            features["swipe_velocity_std"] = float(np.std(velocities))
        
        # Touch duration
        touch_starts = [d for d in data if d.get("event_type") == "start"]
        touch_ends = [d for d in data if d.get("event_type") == "end"]
        
        if touch_starts and touch_ends:
            durations = []
            for start, end in zip(touch_starts, touch_ends):
                duration = end.get("timestamp", 0) - start.get("timestamp", 0)
                if duration > 0:
                    durations.append(duration)
            
            if durations:
                features["touch_duration_mean"] = float(np.mean(durations))
                features["touch_duration_std"] = float(np.std(durations))
        
        return features
    
    def _extract_sensor_features(self, data: List[Dict]) -> Dict[str, Any]:
        """Extract accelerometer/gyroscope features."""
        if not data:
            return {}
        
        # Filter out None values when extracting
        accel_x = [d["accelerometer"]["x"] for d in data 
                   if d.get("accelerometer") and d["accelerometer"].get("x") is not None]
        accel_y = [d["accelerometer"]["y"] for d in data 
                   if d.get("accelerometer") and d["accelerometer"].get("y") is not None]
        accel_z = [d["accelerometer"]["z"] for d in data 
                   if d.get("accelerometer") and d["accelerometer"].get("z") is not None]
        
        gyro_x = [d["gyroscope"]["x"] for d in data 
                  if d.get("gyroscope") and d["gyroscope"].get("x") is not None]
        gyro_y = [d["gyroscope"]["y"] for d in data 
                  if d.get("gyroscope") and d["gyroscope"].get("y") is not None]
        gyro_z = [d["gyroscope"]["z"] for d in data 
                  if d.get("gyroscope") and d["gyroscope"].get("z") is not None]
        
        features = {}
        
        # Accelerometer features
        if accel_x:
            features["accel_x_mean"] = float(np.mean(accel_x))
            features["accel_x_std"] = float(np.std(accel_x))
        if accel_y:
            features["accel_y_mean"] = float(np.mean(accel_y))
            features["accel_y_std"] = float(np.std(accel_y))
        if accel_z:
            features["accel_z_mean"] = float(np.mean(accel_z))
            features["accel_z_std"] = float(np.std(accel_z))
        
        # Magnitude of acceleration
        if accel_x and accel_y and accel_z and len(accel_x) == len(accel_y) == len(accel_z):
            magnitudes = [
                np.sqrt(x**2 + y**2 + z**2) 
                for x, y, z in zip(accel_x, accel_y, accel_z)
            ]
            features["accel_magnitude_mean"] = float(np.mean(magnitudes))
            features["accel_magnitude_std"] = float(np.std(magnitudes))
        
        # Gyroscope features
        if gyro_x:
            features["gyro_x_mean"] = float(np.mean(gyro_x))
            features["gyro_x_std"] = float(np.std(gyro_x))
        if gyro_y:
            features["gyro_y_mean"] = float(np.mean(gyro_y))
            features["gyro_y_std"] = float(np.std(gyro_y))
        if gyro_z:
            features["gyro_z_mean"] = float(np.mean(gyro_z))
            features["gyro_z_std"] = float(np.std(gyro_z))
        
        return features
    
    def _calculate_profile_statistics(
        self, 
        data_type: str,
        features_list: List[Dict]
    ) -> Dict[str, Any]:
        """Calculate statistical profile from multiple feature samples."""
        if not features_list:
            return {}
        
        # Aggregate features
        aggregated = {}
        for features in features_list:
            for key, value in features.items():
                if value is not None and isinstance(value, (int, float)):
                    if key not in aggregated:
                        aggregated[key] = []
                    aggregated[key].append(value)
        
        # Calculate statistics for each feature
        profile = {}
        for key, values in aggregated.items():
            if values:
                profile[key] = {
                    "mean": float(np.mean(values)),
                    "std": float(np.std(values)),
                    "min": float(np.min(values)),
                    "max": float(np.max(values)),
                    "median": float(np.median(values))
                }
        
        return profile
    
    def _calculate_type_score(
        self,
        data_type: BiometricType,
        profile_data: Dict[str, Any],
        current_features_list: List[Dict]
    ) -> Tuple[float, Dict]:
        """Calculate score for specific biometric type."""
        if not profile_data or not current_features_list:
            return 1.0, {}
        
        # Aggregate current features
        current_aggregated = {}
        for features in current_features_list:
            for key, value in features.items():
                if key not in current_aggregated:
                    current_aggregated[key] = []
                current_aggregated[key].append(value)
        
        # Calculate z-scores for each feature
        z_scores = []
        anomalies = {}
        
        for key, current_values in current_aggregated.items():
            if key not in profile_data:
                continue
            
            profile_stats = profile_data[key]
            current_mean = np.mean(current_values)
            
            # Calculate z-score
            if profile_stats["std"] > 0:
                z_score = abs(current_mean - profile_stats["mean"]) / profile_stats["std"]
                z_scores.append(z_score)
                
                # Flag anomaly if z-score > 2 (95% confidence)
                if z_score > 2:
                    anomalies[key] = {
                        "z_score": float(z_score),
                        "expected": profile_stats["mean"],
                        "actual": float(current_mean)
                    }
        
        if not z_scores:
            return 1.0, {}
        
        # Convert average z-score to trust score (0-1)
        avg_z_score = np.mean(z_scores)
        
        # Use sigmoid-like function to convert z-score to score
        # z=0 -> score=1.0, z=3 -> score~0.05
        trust_score = 1 / (1 + np.exp(avg_z_score - 2))
        
        return float(trust_score), anomalies
    
    def _calculate_combined_score(self, scores: Dict[str, float]) -> float:
        if not scores:
            return 1.0
        
        # Determine device category from score keys
        has_desktop = any('_desktop' in k for k in scores.keys())
        has_mobile = any('_mobile' in k for k in scores.keys())
        
        # Weights matching auth_service.py
        if has_mobile and not has_desktop:
            weights = {"KEYSTROKE": 0.5, "TOUCH": 0.3, "SENSOR_FUSION": 0.2}
        else:
            weights = {"KEYSTROKE": 0.7, "MOUSE": 0.3}
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for bio_type_key, score in scores.items():
            if bio_type_key.endswith('_desktop'):
                base_type = bio_type_key[:-8]
            elif bio_type_key.endswith('_mobile'):
                base_type = bio_type_key[:-7]
            else:
                base_type = bio_type_key
            
            weight = weights.get(base_type, 0.25)
            weighted_sum += score * weight
            total_weight += weight
        
        if total_weight > 0:
            return weighted_sum / total_weight
        
        return 1.0
    
    async def _get_user_profiles(self, user_id: UUID) -> Dict[str, BiometricProfile]:
        """Get all biometric profiles for user."""
        result = await self.db.execute(
            select(BiometricProfile).where(BiometricProfile.user_id == user_id)
        )
        profiles = result.scalars().all()
        return {p.data_type: p for p in profiles}
    
    async def _store_trust_score(
        self,
        session_id: UUID,
        user_id: UUID,
        score: float,
        scores: Dict[str, float],
        anomaly_details: Dict = None
    ):
        """Store trust score in history."""
        history = TrustScoreHistory(
            session_id=session_id,
            user_id=user_id,
            score=score,
            keystroke_score=scores.get("KEYSTROKE"),
            mouse_score=scores.get("MOUSE"),
            touch_score=scores.get("TOUCH"),
            sensor_score=scores.get("SENSOR_FUSION"),
            anomaly_details=anomaly_details
        )
        self.db.add(history)
    
    async def _update_session_trust_score(self, session_id: UUID, score: float):
        """Update session's current trust score."""
        result = await self.db.execute(
            select(Session).where(Session.id == session_id)
        )
        session = result.scalar_one_or_none()
        if session:
            session.trust_score = score
    
    async def _log_anomaly_event(
        self,
        user_id: UUID,
        session_id: UUID,
        trust_score: float,
        anomaly_details: Dict
    ):
        """Log anomaly detection event and send alert email."""
        # Get session and user info for email
        session_result = await self.db.execute(
            select(Session).where(Session.id == session_id)
        )
        session = session_result.scalar_one_or_none()
        
        user_result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()
        
        # Log event
        event = SecurityEvent(
            user_id=user_id,
            session_id=session_id,
            event_type="ANOMALY_DETECTED",
            details={
                "trust_score": trust_score,
                "threshold": settings.trust_score_threshold,
                "anomalies": anomaly_details
            },
            ip_address=session.ip_address if session else None,
            user_agent=session.user_agent if session else None
        )
        self.db.add(event)
        
        # Send email alert if user exists
        if user and user.email:
            await email_service.send_suspicious_activity_alert(
                to_email=user.email,
                username=user.username,
                trust_score=trust_score,
                ip_address=session.ip_address if session else None,
                user_agent=session.user_agent if session else None,
                anomaly_details=anomaly_details
            )
