#[cfg(feature = "persist-sqlite")]
use sqlx::{SqlitePool, Row};
#[cfg(feature = "persist-sqlite")]
use serde_json;

use std::net::IpAddr;

#[cfg(feature = "persist-sqlite")]
pub struct TokenDbStore {
    pool: SqlitePool,
}

#[cfg(feature = "persist-sqlite")]
impl TokenDbStore {
    pub async fn new(db_path: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect(db_path).await?;

        // tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS verified_tokens (
                token TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                tls_fingerprint TEXT NOT NULL,
                browser_fingerprint TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                request_count INTEGER NOT NULL,
                suspicious_score INTEGER NOT NULL,
                ip_changes INTEGER NOT NULL,
                user_agent_changes INTEGER NOT NULL,
                concurrent_sessions INTEGER NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await?;

        // index
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_token ON verified_tokens(token)"
        )
        .execute(&pool)
        .await?;

        // Clean up expired tokens
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON verified_tokens(created_at)"
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn save_token(&self, token: &str, client: &crate::VerifiedClient) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO verified_tokens (
                token,
                ip,
                user_agent,
                tls_fingerprint,
                browser_fingerprint,
                created_at,
                last_seen,
                request_count,
                suspicious_score,
                ip_changes,
                user_agent_changes,
                concurrent_sessions
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(token) DO UPDATE SET
                ip = ?2,
                user_agent = ?3,
                last_seen = ?7,
                request_count = ?8,
                suspicious_score = ?9,
                ip_changes = ?10,
                user_agent_changes = ?11,
                concurrent_sessions = ?12
            "#
        )
        .bind(token)
        .bind(client.ip.to_string())
        .bind(&client.user_agent)
        .bind(&client.tls_fingerprint)
        .bind(&client.browser_fingerprint)
        .bind(client.created_at as i64)
        .bind(client.last_seen as i64)
        .bind(client.request_count as i64)
        .bind(client.suspicious_score as i64)
        .bind(client.ip_changes as i64)
        .bind(client.user_agent_changes as i64)
        .bind(client.concurrent_sessions as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_token(&self, token: &str) -> Result<Option<crate::VerifiedClient>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT token, ip, user_agent, tls_fingerprint, browser_fingerprint,
                   created_at, last_seen, request_count, suspicious_score,
                   ip_changes, user_agent_changes, concurrent_sessions
            FROM verified_tokens
            WHERE token = ?1
            "#
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let ip_str: String = row.get("ip");
                let ip: IpAddr = ip_str.parse().map_err(|_| sqlx::Error::Decode(
                    Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid IP"))
                ))?;

                Ok(Some(crate::VerifiedClient {
                    token: row.get("token"),
                    ip,
                    user_agent: row.get("user_agent"),
                    tls_fingerprint: row.get("tls_fingerprint"),
                    browser_fingerprint: row.get("browser_fingerprint"),
                    created_at: row.get::<i64, _>("created_at") as u64,
                    last_seen: row.get::<i64, _>("last_seen") as u64,
                    request_count: row.get::<i64, _>("request_count") as u32,
                    suspicious_score: row.get::<i64, _>("suspicious_score") as u32,
                    ip_changes: row.get::<i64, _>("ip_changes") as u32,
                    user_agent_changes: row.get::<i64, _>("user_agent_changes") as u32,
                    concurrent_sessions: row.get::<i64, _>("concurrent_sessions") as u32,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_token(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM verified_tokens WHERE token = ?1")
            .bind(token)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn cleanup_expired(&self, max_age_seconds: u64) -> Result<u64, sqlx::Error> {
        let cutoff = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - max_age_seconds) as i64;

        let result = sqlx::query("DELETE FROM verified_tokens WHERE created_at < ?1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

// No-op implementation when feature is disabled
#[cfg(not(feature = "persist-sqlite"))]
pub struct TokenDbStore;

#[cfg(not(feature = "persist-sqlite"))]
impl TokenDbStore {
    pub async fn new(_db_path: &str) -> Result<Self, String> {
        Ok(Self)
    }
}
