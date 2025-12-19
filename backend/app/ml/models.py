import numpy as np
import pickle
import base64
from typing import Dict, List, Tuple, Optional, Any
from sklearn.svm import OneClassSVM
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import logging

logger = logging.getLogger(__name__)


class BiometricMLModel:
    FEATURE_SETS = {
        "KEYSTROKE": [
            "hold_time_mean", "hold_time_std", "hold_time_median", "hold_time_min", "hold_time_max",
            "flight_time_mean", "flight_time_std", "flight_time_median", "flight_time_min", "flight_time_max",
            "typing_speed", "pause_rate", "rhythm_consistency"
        ],
        "MOUSE": [
            "velocity_mean", "velocity_std", "velocity_median", "velocity_max",
            "acceleration_mean", "acceleration_std", "acceleration_max",
            "jerk_mean", "jerk_std",
            "direction_changes", "straightness_index",
            "movement_efficiency", "pause_frequency"
        ],
        "TOUCH": [
            "pressure_mean", "pressure_std", "pressure_median",
            "touch_area_mean", "touch_area_std",
            "touch_duration_mean", "touch_duration_std",
            "swipe_velocity_mean", "swipe_velocity_std",
            "swipe_straightness"
        ],
        "SENSOR_FUSION": [
            "accel_magnitude_mean", "accel_magnitude_std",
            "gyro_magnitude_mean", "gyro_magnitude_std",
            "device_stability", "tilt_consistency"
        ]
    }
    
    def __init__(self, biometric_type: str):
        self.biometric_type = biometric_type
        
        if biometric_type.endswith('_desktop'):
            base_type = biometric_type[:-8]
        elif biometric_type.endswith('_mobile'):
            base_type = biometric_type[:-7]
        else:
            base_type = biometric_type
        
        self.feature_names = self.FEATURE_SETS.get(base_type, [])
        self.is_trained = False
        self.min_samples = 30
        
        self.ocsvm = Pipeline([
            ('scaler', StandardScaler()),
            ('model', OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.05,
                shrinking=True,
                cache_size=200
            ))
        ])
        
        self.isolation_forest = Pipeline([
            ('scaler', StandardScaler()),
            ('model', IsolationForest(
                n_estimators=150,
                contamination=0.05,
                max_samples='auto',
                max_features=1.0,
                bootstrap=True,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
        self.feature_stats = {}
        self.training_samples_count = 0
    
    def _features_to_vector(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        if not features:
            return None
        
        vector = []
        for feature_name in self.feature_names:
            value = features.get(feature_name)
            if value is None:
                vector.append(0.0)
            else:
                vector.append(float(value))
        
        return np.array(vector)
    
    def _prepare_training_data(self, samples: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        vectors = []
        for sample in samples:
            vec = self._features_to_vector(sample)
            if vec is not None:
                vectors.append(vec)
        
        if len(vectors) < self.min_samples:
            return None
        
        return np.array(vectors)
    
    def train(self, training_samples: List[Dict[str, Any]]) -> bool:
        X = self._prepare_training_data(training_samples)
        
        if X is None:
            logger.warning(f"Not enough training data for {self.biometric_type}. "
                          f"Got {len(training_samples)}, need {self.min_samples}")
            return False
        
        try:
            self.ocsvm.fit(X)
            self.isolation_forest.fit(X)
            
            self.feature_stats = {
                'mean': np.mean(X, axis=0).tolist(),
                'std': np.std(X, axis=0).tolist(),
                'min': np.min(X, axis=0).tolist(),
                'max': np.max(X, axis=0).tolist()
            }
            
            self.training_samples_count = len(X)
            self.is_trained = True
            
            logger.info(f"Successfully trained {self.biometric_type} model with {len(X)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training {self.biometric_type} model: {e}")
            return False
    
    def predict(self, features: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        if not self.is_trained:
            return 1.0, {"status": "not_trained"}
        
        vec = self._features_to_vector(features)
        if vec is None:
            return 1.0, {"status": "no_features"}
        
        X = vec.reshape(1, -1)
        
        try:
            ocsvm_pred = self.ocsvm.predict(X)[0]
            iforest_pred = self.isolation_forest.predict(X)[0]
            
            ocsvm_score = self.ocsvm.decision_function(X)[0]
            iforest_score = self.isolation_forest.decision_function(X)[0]
            
            logger.debug(f"Raw scores - OCSVM: {ocsvm_score:.4f}, IForest: {iforest_score:.4f}")
            
            ocsvm_trust = self._normalize_score(ocsvm_score, method='ocsvm')
            iforest_trust = self._normalize_score(iforest_score, method='iforest')
            distance_trust = self._calculate_distance_trust(vec)
            
            is_mobile = '_mobile' in self.biometric_type
            
            if is_mobile:
                combined_trust = 0.30 * ocsvm_trust + 0.50 * iforest_trust + 0.20 * distance_trust
            else:
                combined_trust = 0.25 * ocsvm_trust + 0.35 * iforest_trust + 0.40 * distance_trust
            
            anomalous_features = self._identify_anomalous_features(vec)
            
            details = {
                "status": "analyzed",
                "ocsvm_prediction": "normal" if ocsvm_pred == 1 else "anomaly",
                "iforest_prediction": "normal" if iforest_pred == 1 else "anomaly",
                "ocsvm_trust": round(ocsvm_trust, 3),
                "iforest_trust": round(iforest_trust, 3),
                "distance_trust": round(distance_trust, 3),
                "combined_trust": round(combined_trust, 3),
                "raw_scores": {
                    "ocsvm": round(ocsvm_score, 4),
                    "iforest": round(iforest_score, 4)
                },
                "anomalous_features": anomalous_features
            }
            
            return combined_trust, details
            
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            return 1.0, {"status": "error", "message": str(e)}
    
    def _normalize_score(self, score: float, method: str = 'ocsvm') -> float:
        is_mobile = '_mobile' in self.biometric_type
        
        if method == 'ocsvm':
            multiplier = 1.5 if is_mobile else 2.0
            trust = 1 / (1 + np.exp(-score * multiplier))
        elif method == 'iforest':
            multiplier = 3.0 if is_mobile else 5.0
            trust = 1 / (1 + np.exp(-score * multiplier))
        else:
            trust = 1 / (1 + np.exp(-score))
        
        return float(np.clip(trust, 0.0, 1.0))
    
    def _calculate_distance_trust(self, vec: np.ndarray) -> float:
        if not self.feature_stats or 'mean' not in self.feature_stats:
            return 0.5
        
        means = np.array(self.feature_stats['mean'])
        stds = np.array(self.feature_stats['std'])
        stds = np.where(stds < 1e-10, 1e-10, stds)
        
        z_scores = np.abs((vec - means) / stds)
        
        is_mobile = '_mobile' in self.biometric_type
        is_keystroke = 'KEYSTROKE' in self.biometric_type
        
        if is_mobile and is_keystroke:
            z_scores = np.clip(z_scores, 0, 3)
            avg_z = np.mean(z_scores)
            trust = np.exp(-avg_z / 3)
        elif is_mobile:
            z_scores = np.clip(z_scores, 0, 4)
            avg_z = np.mean(z_scores)
            trust = np.exp(-avg_z / 2.5)
        else:
            avg_z = np.mean(z_scores)
            trust = np.exp(-avg_z / 2)
        
        return float(np.clip(trust, 0.0, 1.0))
    
    def _identify_anomalous_features(self, vec: np.ndarray, threshold: float = 2.0) -> List[str]:
        anomalous = []
        
        if not self.feature_stats or 'mean' not in self.feature_stats:
            return anomalous
        
        means = np.array(self.feature_stats['mean'])
        stds = np.array(self.feature_stats['std'])
        stds = np.where(stds == 0, 1e-10, stds)
        
        z_scores = np.abs((vec - means) / stds)
        
        for i, (z, name) in enumerate(zip(z_scores, self.feature_names)):
            if z > threshold:
                anomalous.append({
                    "feature": name,
                    "z_score": round(float(z), 2),
                    "expected": round(float(means[i]), 3),
                    "actual": round(float(vec[i]), 3)
                })
        
        return anomalous
    
    def serialize(self) -> str:
        model_data = {
            'biometric_type': self.biometric_type,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names,
            'feature_stats': self.feature_stats,
            'training_samples_count': self.training_samples_count,
            'ocsvm': self.ocsvm if self.is_trained else None,
            'isolation_forest': self.isolation_forest if self.is_trained else None
        }
        
        pickled = pickle.dumps(model_data)
        return base64.b64encode(pickled).decode('utf-8')
    
    @classmethod
    def deserialize(cls, data: str) -> 'BiometricMLModel':
        pickled = base64.b64decode(data.encode('utf-8'))
        model_data = pickle.loads(pickled)
        
        model = cls(model_data['biometric_type'])
        model.is_trained = model_data['is_trained']
        model.feature_names = model_data['feature_names']
        model.feature_stats = model_data['feature_stats']
        model.training_samples_count = model_data['training_samples_count']
        
        if model_data['ocsvm']:
            model.ocsvm = model_data['ocsvm']
        if model_data['isolation_forest']:
            model.isolation_forest = model_data['isolation_forest']
        
        return model


class BiometricModelManager:
    def __init__(self):
        self.models: Dict[str, BiometricMLModel] = {}
    
    def get_or_create_model(self, biometric_type: str) -> BiometricMLModel:
        if biometric_type not in self.models:
            self.models[biometric_type] = BiometricMLModel(biometric_type)
        return self.models[biometric_type]
    
    def train_model(self, biometric_type: str, training_samples: List[Dict[str, Any]]) -> bool:
        model = self.get_or_create_model(biometric_type)
        return model.train(training_samples)
    
    def predict(self, biometric_type: str, features: Dict[str, Any]) -> Tuple[float, Dict]:
        model = self.get_or_create_model(biometric_type)
        return model.predict(features)
    
    def serialize_all(self) -> Dict[str, str]:
        return {
            bio_type: model.serialize()
            for bio_type, model in self.models.items()
        }
    
    def load_model(self, biometric_type: str, serialized_data: str):
        self.models[biometric_type] = BiometricMLModel.deserialize(serialized_data)
    
    def get_training_status(self) -> Dict[str, Any]:
        return {
            bio_type: {
                "is_trained": model.is_trained,
                "samples_count": model.training_samples_count,
                "min_required": model.min_samples
            }
            for bio_type, model in self.models.items()
        }
