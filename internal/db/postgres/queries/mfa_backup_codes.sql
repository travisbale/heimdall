-- name: CreateBackupCodes :batchexec
INSERT INTO mfa_backup_codes (user_id, code_hash)
VALUES ($1, $2);

-- name: GetUnusedBackupCodesByUserID :many
SELECT * FROM mfa_backup_codes
WHERE user_id = $1 AND used = false
ORDER BY created_at ASC;

-- name: MarkBackupCodeUsed :exec
UPDATE mfa_backup_codes
SET used = true, used_at = now()
WHERE id = $1;

-- name: DeleteBackupCodesByUserID :exec
DELETE FROM mfa_backup_codes WHERE user_id = $1;

-- name: CountUnusedBackupCodes :one
SELECT COUNT(*) FROM mfa_backup_codes
WHERE user_id = $1 AND used = false;
