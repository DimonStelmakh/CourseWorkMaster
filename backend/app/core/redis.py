import redis.asyncio as redis
from app.core.config import settings
from typing import Optional
import json


class RedisClient:
    def __init__(self):
        self._client: Optional[redis.Redis] = None
    
    async def connect(self):
        self._client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
    
    async def disconnect(self):
        if self._client:
            await self._client.close()
    
    @property
    def client(self) -> redis.Redis:
        if not self._client:
            raise RuntimeError("Redis client not initialized")
        return self._client
    
    # Session operations
    async def set_session(self, session_id: str, data: dict, ttl: int = 1800):
        await self.client.setex(
            f"session:{session_id}",
            ttl,
            json.dumps(data)
        )
    
    async def get_session(self, session_id: str) -> Optional[dict]:
        data = await self.client.get(f"session:{session_id}")
        return json.loads(data) if data else None
    
    async def delete_session(self, session_id: str):
        await self.client.delete(f"session:{session_id}")
    
    async def extend_session(self, session_id: str, ttl: int = 1800):
        await self.client.expire(f"session:{session_id}", ttl)
    
    # Trust score caching
    async def set_trust_score(self, session_id: str, score: float, ttl: int = 300):
        await self.client.setex(
            f"trust:{session_id}",
            ttl,
            str(score)
        )
    
    async def get_trust_score(self, session_id: str) -> Optional[float]:
        score = await self.client.get(f"trust:{session_id}")
        return float(score) if score else None
    
    # Rate limiting
    async def check_rate_limit(self, key: str, max_requests: int, window: int) -> bool:
        current = await self.client.incr(f"rate:{key}")
        if current == 1:
            await self.client.expire(f"rate:{key}", window)
        return current <= max_requests
    
    # Biometric data buffer - now session-based to avoid mixing data from different devices
    async def append_biometric_buffer(self, session_id: str, data_type: str, data: dict):
        await self.client.rpush(
            f"bio_buffer:{session_id}:{data_type}",
            json.dumps(data)
        )
        # Keep buffer for 1 hour
        await self.client.expire(f"bio_buffer:{session_id}:{data_type}", 3600)
    
    async def get_biometric_buffer(self, session_id: str, data_type: str) -> list:
        data = await self.client.lrange(f"bio_buffer:{session_id}:{data_type}", 0, -1)
        return [json.loads(item) for item in data]
    
    async def clear_biometric_buffer(self, session_id: str, data_type: str):
        await self.client.delete(f"bio_buffer:{session_id}:{data_type}")


redis_client = RedisClient()


async def get_redis() -> RedisClient:
    return redis_client
