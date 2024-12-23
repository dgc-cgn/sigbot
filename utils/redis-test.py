# file: redis_example.py

import redis

# Connect to Redis (assuming it's running on localhost:6379)
# decode_responses=True -> get/set strings (instead of bytes)
# r = redis.Redis(host="beelink", port=6379, db=0, decode_responses=True)
r = redis.Redis(host="beelink")
# Store a key-value pair
r.set("mykey", "Hello from Python!")

# Retrieve the value
value = r.get("mykey")

print(f"The value for 'mykey' is: {value}")
