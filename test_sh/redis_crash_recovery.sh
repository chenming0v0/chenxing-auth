#!/usr/bin/env bash
set -Eeuo pipefail

# Issue #494: prove that Redis acknowledges credential-state transitions only
# after they are durable enough to survive an immediate process crash.

REDIS_IMAGE="${REDIS_CRASH_TEST_IMAGE:-redis:7-alpine}"
resource_suffix="${GITHUB_RUN_ID:-local}-$$"
container="chenxing-redis-crash-${resource_suffix}"
volume="chenxing-redis-crash-${resource_suffix}"
resource_owner="${resource_suffix}-${RANDOM:-0}"

fail() {
    printf 'Redis crash/recovery assertion failed: %s\n' "$1" >&2
    exit 1
}

assert_owned_container() {
    local owner
    owner="$(docker container inspect \
        --format '{{ index .Config.Labels "com.chenxing.redis-crash.owner" }}' \
        "$container" 2>/dev/null || true)"
    [[ "$owner" == "$resource_owner" ]] \
        || fail "refusing to operate on a container not owned by this run: $container"
}

cleanup() {
    local status=$?
    local container_owner volume_owner
    trap - EXIT
    set +e
    container_owner="$(docker container inspect \
        --format '{{ index .Config.Labels "com.chenxing.redis-crash.owner" }}' \
        "$container" 2>/dev/null || true)"
    if [[ "$container_owner" == "$resource_owner" ]]; then
        if (( status != 0 )); then
            docker logs "$container" >&2
        fi
        docker rm --force "$container" >/dev/null 2>&1
    fi
    volume_owner="$(docker volume inspect \
        --format '{{ index .Labels "com.chenxing.redis-crash.owner" }}' \
        "$volume" 2>/dev/null || true)"
    if [[ "$volume_owner" == "$resource_owner" ]]; then
        docker volume rm --force "$volume" >/dev/null 2>&1
    fi
    exit "$status"
}
trap cleanup EXIT

start_redis() {
    if docker container inspect "$container" >/dev/null 2>&1; then
        fail "refusing to reuse an existing container: $container"
    fi
    docker run --detach \
        --name "$container" \
        --label "com.chenxing.redis-crash.owner=$resource_owner" \
        --network none \
        --volume "$volume:/data" \
        "$REDIS_IMAGE" \
        redis-server \
        --appendonly yes \
        --appendfsync always \
        --no-appendfsync-on-rewrite no \
        --aof-load-truncated no \
        --aof-use-rdb-preamble yes \
        --save "" \
        --dir /data \
        --appenddirname appendonlydir \
        --appendfilename appendonly.aof >/dev/null
}

redis() {
    docker exec "$container" redis-cli --raw "$@"
}

wait_for_redis() {
    local attempt
    for attempt in $(seq 1 80); do
        if [[ "$(redis PING 2>/dev/null || true)" == "PONG" ]]; then
            return 0
        fi
        sleep 0.25
    done
    fail "Redis did not become ready"
}

assert_missing() {
    local key=$1
    [[ "$(redis EXISTS "$key")" == "0" ]] || fail "key resurrected after crash: $key"
}

assert_value() {
    local key=$1
    local expected=$2
    local actual
    actual="$(redis GET "$key")"
    [[ "$actual" == "$expected" ]] || fail "unexpected value after crash: $key"
}

assert_set_member() {
    local key=$1
    local member=$2
    [[ "$(redis SISMEMBER "$key" "$member")" == "1" ]] \
        || fail "set member missing after crash: $key"
}

assert_not_set_member() {
    local key=$1
    local member=$2
    [[ "$(redis SISMEMBER "$key" "$member")" == "0" ]] \
        || fail "removed set member resurrected after crash: $key"
}

if docker volume inspect "$volume" >/dev/null 2>&1; then
    fail "refusing to reuse an existing volume: $volume"
fi
docker volume create \
    --label "com.chenxing.redis-crash.owner=$resource_owner" \
    "$volume" >/dev/null
volume_owner="$(docker volume inspect \
    --format '{{ index .Labels "com.chenxing.redis-crash.owner" }}' \
    "$volume")"
[[ "$volume_owner" == "$resource_owner" ]] \
    || fail "created volume ownership label mismatch: $volume"
start_redis
wait_for_redis

prefix="chenxing:crash-test:${resource_suffix}"

# Authorization-code consumption is authoritative in Redis. Once GETDEL is
# acknowledged, recovery must not expose the code again.
authorization_code_key="${prefix}:authorization-code:consumed"
authorization_code_payload='{"state":"issued"}'
redis SET "$authorization_code_key" "$authorization_code_payload" >/dev/null
[[ "$(redis GETDEL "$authorization_code_key")" == "$authorization_code_payload" ]] \
    || fail "authorization code was not consumed"

# Model the production rotation transaction: successor creation, predecessor
# deletion, index replacement and the Consumed tombstone are one acknowledged
# transition and must recover together.
rotation_old_key="${prefix}:refresh:rotation:old"
rotation_successor_key="${prefix}:refresh:rotation:successor"
consumed_tombstone_key="${prefix}:refresh:tombstone:consumed"
rotation_family_index="${prefix}:refresh:index:family"
rotation_grant_index="${prefix}:refresh:index:grant"
rotation_client_index="${prefix}:refresh:index:client"
rotation_old_member="old-token-hash"
rotation_successor_member="successor-token-hash"
rotation_old_payload='{"state":"active","generation":1}'
rotation_successor_payload='{"state":"active","generation":2}'
consumed_tombstone_payload='{"state":"consumed","generation":1}'

redis SET "$rotation_old_key" "$rotation_old_payload" >/dev/null
redis SADD "$rotation_family_index" "$rotation_old_member" >/dev/null
redis SADD "$rotation_grant_index" "$rotation_old_member" >/dev/null
redis SADD "$rotation_client_index" "$rotation_old_member" >/dev/null
rotation_result="$(redis EVAL '
local current = redis.call("GET", KEYS[1])
if current ~= ARGV[1] then return 0 end
redis.call("SETEX", KEYS[2], 600, ARGV[2])
redis.call("DEL", KEYS[1])
for index = 4, 6 do
    redis.call("SREM", KEYS[index], ARGV[4])
    redis.call("SADD", KEYS[index], ARGV[5])
end
redis.call("SETEX", KEYS[3], 600, ARGV[3])
return 1
' 6 \
    "$rotation_old_key" \
    "$rotation_successor_key" \
    "$consumed_tombstone_key" \
    "$rotation_family_index" \
    "$rotation_grant_index" \
    "$rotation_client_index" \
    "$rotation_old_payload" \
    "$rotation_successor_payload" \
    "$consumed_tombstone_payload" \
    "$rotation_old_member" \
    "$rotation_successor_member")"
[[ "$rotation_result" == "1" ]] || fail "refresh token rotation did not commit"

# Model explicit family revocation: the active token and index members disappear,
# while the ExplicitRevoke tombstone and family revoked marker remain authoritative.
revoked_token_key="${prefix}:refresh:revoked:active"
explicit_tombstone_key="${prefix}:refresh:tombstone:explicit-revoke"
family_revoked_key="${prefix}:refresh:family-revoked"
revoked_family_index="${prefix}:refresh:revoked:index:family"
revoked_grant_index="${prefix}:refresh:revoked:index:grant"
revoked_client_index="${prefix}:refresh:revoked:index:client"
revoked_member="revoked-token-hash"
revoked_payload='{"state":"active","generation":4}'
explicit_tombstone_payload='{"state":"explicit_revoke","generation":4}'
family_revoked_payload='{"state":"family_revoked"}'

redis SET "$revoked_token_key" "$revoked_payload" >/dev/null
redis SADD "$revoked_family_index" "$revoked_member" >/dev/null
redis SADD "$revoked_grant_index" "$revoked_member" >/dev/null
redis SADD "$revoked_client_index" "$revoked_member" >/dev/null
revoke_result="$(redis EVAL '
if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
redis.call("DEL", KEYS[1])
for index = 4, 6 do
    redis.call("SREM", KEYS[index], ARGV[1])
end
redis.call("SETEX", KEYS[2], 600, ARGV[2])
redis.call("SETEX", KEYS[3], 600, ARGV[3])
return 1
' 6 \
    "$revoked_token_key" \
    "$explicit_tombstone_key" \
    "$family_revoked_key" \
    "$revoked_family_index" \
    "$revoked_grant_index" \
    "$revoked_client_index" \
    "$revoked_member" \
    "$explicit_tombstone_payload" \
    "$family_revoked_payload")"
[[ "$revoke_result" == "1" ]] || fail "refresh token revocation did not commit"

# Model session revocation as removal of the cached Session projection and a
# monotonic user epoch watermark. Both writes are one acknowledged transition,
# so recovery must not resurrect the projection or lose the newer epoch.
session_revoked_projection_key="${prefix}:session:revoked:projection"
session_revoked_epoch_key="${prefix}:session:revoked:epoch"
session_revoked_projection_payload='{"state":"active","epoch":6}'
session_previous_epoch="6"
session_revoked_epoch="7"

redis SET "$session_revoked_projection_key" "$session_revoked_projection_payload" >/dev/null
redis SETEX "$session_revoked_epoch_key" 600 "$session_previous_epoch" >/dev/null
session_revoke_result="$(redis EVAL '
local current = redis.call("GET", KEYS[1])
if current ~= ARGV[1] then return 0 end
redis.call("DEL", KEYS[1])
local current_epoch = redis.call("GET", KEYS[2])
if not current_epoch or tonumber(current_epoch) < tonumber(ARGV[2]) then
    redis.call("SETEX", KEYS[2], 600, ARGV[2])
elseif redis.call("TTL", KEYS[2]) < 600 then
    redis.call("EXPIRE", KEYS[2], 600)
end
return 1
' 2 \
    "$session_revoked_projection_key" \
    "$session_revoked_epoch_key" \
    "$session_revoked_projection_payload" \
    "$session_revoked_epoch")"
[[ "$session_revoke_result" == "1" ]] \
    || fail "session revocation projection did not commit"

# Crash immediately after all mutating commands returned. With appendfsync always,
# every state below is inside the accepted RPO and must survive on the same volume.
assert_owned_container
docker kill --signal KILL "$container" >/dev/null
assert_owned_container
docker rm "$container" >/dev/null
start_redis
wait_for_redis

assert_missing "$authorization_code_key"
assert_missing "$rotation_old_key"
assert_value "$rotation_successor_key" "$rotation_successor_payload"
assert_value "$consumed_tombstone_key" "$consumed_tombstone_payload"
assert_not_set_member "$rotation_family_index" "$rotation_old_member"
assert_set_member "$rotation_family_index" "$rotation_successor_member"
assert_not_set_member "$rotation_grant_index" "$rotation_old_member"
assert_set_member "$rotation_grant_index" "$rotation_successor_member"
assert_not_set_member "$rotation_client_index" "$rotation_old_member"
assert_set_member "$rotation_client_index" "$rotation_successor_member"

assert_missing "$revoked_token_key"
assert_value "$explicit_tombstone_key" "$explicit_tombstone_payload"
assert_value "$family_revoked_key" "$family_revoked_payload"
assert_not_set_member "$revoked_family_index" "$revoked_member"
assert_not_set_member "$revoked_grant_index" "$revoked_member"
assert_not_set_member "$revoked_client_index" "$revoked_member"
assert_missing "$session_revoked_projection_key"
assert_value "$session_revoked_epoch_key" "$session_revoked_epoch"

[[ "$(redis CONFIG GET appendonly | tail -n 1)" == "yes" ]] \
    || fail "appendonly is not enabled after recovery"
[[ "$(redis CONFIG GET appendfsync | tail -n 1)" == "always" ]] \
    || fail "appendfsync is not always after recovery"
[[ "$(redis CONFIG GET aof-load-truncated | tail -n 1)" == "no" ]] \
    || fail "truncated AOF recovery is not fail-closed"
persistence_info="$(redis INFO persistence | tr -d '\r')"
grep -qx 'aof_enabled:1' <<<"$persistence_info" \
    || fail "AOF is not enabled after recovery"
grep -qx 'aof_last_write_status:ok' <<<"$persistence_info" \
    || fail "Redis reports a failed AOF write"

printf 'Redis crash/recovery credential-state checks passed.\n'
