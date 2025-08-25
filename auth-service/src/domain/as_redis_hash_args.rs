pub trait AsRedisHashArgs: Send + Sync {
    fn as_redis_hash_args(&self) -> Vec<(String, String)>;
}
