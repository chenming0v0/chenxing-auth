# Session Storage Consistency Design

## Goal

Make PostgreSQL session metadata and the Redis session projection converge reliably when either storage is unavailable during save or revocation, without allowing stale Redis data to authenticate a revoked session.

## Consistency model

PostgreSQL is the authoritative session store. A session row contains the durable metadata and an encrypted copy of the serialized session payload needed to reconstruct the browser CSRF credential. Redis is an idempotent projection used by the Redis-only `SessionStore` mode and for operational cache compatibility; metadata-enabled authentication validates the PostgreSQL row before returning a session.

There is no cross-database transaction. Each metadata-enabled mutation commits the PostgreSQL fact and a session outbox record in one PostgreSQL transaction. A retrying worker applies the outbox operation to Redis. A Redis failure therefore leaves a visible pending operation rather than an orphaned metadata row or an authentication-valid stale cache entry.

## Mutation flow

- `save`: insert the metadata row, encrypt the serialized session after its generated id is known, and enqueue `sync_session` in one transaction. After commit, try the operation immediately; failure is logged and retained for worker retry.
- `revoke`: mark the row revoked and enqueue `revoke_session` in one transaction. A missing Redis connection does not undo the authoritative revocation.
- `revoke_for_user`: lock and validate the target row, mark it revoked, and enqueue `revoke_session` in one transaction.
- `revoke_all_for_user`: mark all currently active rows revoked and enqueue one `revoke_session` operation per affected token plus one `revoke_user` operation carrying the transaction timestamp. The worker deletes exact token keys even if the user or session rows are later deleted, and updates the Redis revocation marker for Redis-only stores. Outbox event user ids are retained independently of the user foreign key so deleting a user cannot discard the marker operation.

Outbox processing is idempotent. A `sync_session` operation locks and reads the current row until its Redis projection finishes: active rows are written with the remaining TTL, while revoked, expired, or missing rows are deleted. This prevents a delayed save event from restoring a session that was revoked before the event was delivered, including the race where revocation commits while a projection is in flight.

## Read flow

With metadata enabled, `find` queries PostgreSQL by token hash and requires an unrevoked, unexpired row. The hot path is an unlocked read: new rows reconstruct the session from the encrypted PostgreSQL payload and do not depend on Redis availability. Rows created before the encrypted payload migration may use Redis only as a legacy payload fallback, and that Redis I/O must not run under a session row lock (Issue #432). `FOR UPDATE` is taken only for the short idle-renewal write that bumps `last_seen_at`, optionally backfills the durable payload, and enqueues `sync_session`; renewal re-validates activity under the lock so a concurrent revocation still wins. Redis-only stores retain their existing Redis behavior.

## Failure handling and observability

Outbox rows have an availability timestamp, attempt count, processed timestamp, and last error. Failed delivery schedules exponential backoff capped at five minutes. The worker logs the outbox id, operation, attempt count, and error without logging token values. The database row remains pending until delivery succeeds, making recovery state queryable.

## Testing

Integration tests cover real PostgreSQL and Redis instances plus a deliberately unreachable Redis endpoint for save, single revoke, user revoke, and batch revoke. Each test verifies the PostgreSQL authority immediately after the injected failure, confirms the outbox is pending, then restores Redis and processes the outbox to verify the projection converges. A deletion-order test verifies that a pending batch revoke still removes stale Redis keys after its user and session rows are deleted.
