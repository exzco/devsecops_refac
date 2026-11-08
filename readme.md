## 项目依赖
- go 1.26.0
- postgres 
- redis 

### redis 
redis-cli 
INFO keyspace  
SELECT 10 
LRANGE sast:scan:queue 0 -1 

### postgres
client-cli:
\d
\c
\dt
\l