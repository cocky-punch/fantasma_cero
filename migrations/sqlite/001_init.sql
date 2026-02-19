CREATE TABLE pow_challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id BLOB UNIQUE,
    ip_addr TEXT NOT NULL CHECK(LENGTH(ip_addr) <= 45), /*or BLOB*/
    difficulty_level INTEGER NOT NULL,
    user_agent TEXT,
    asn INTEGER,
    asn_org TEXT,
    country_iso3_code TEXT,
    inserted_at INTEGER NOT NULL,
    updated_at INTEGER
);
-- CREATE INDEX idx_pow_inserted_at ON pow_challenges(inserted_at);


CREATE TABLE feedback_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id BLOB UNIQUE, /*provided by user*/
    pow_challenge_id INTEGER, /*may be or become null*/
    ip_addr TEXT NOT NULL CHECK(LENGTH(ip_addr) <= 45), /*or BLOB*/
    category TEXT,
    message TEXT NOT NULL,
    contact_details TEXT,
    user_agent TEXT,
    meta_data TEXT,
    inserted_at INTEGER NOT NULL,
    updated_at INTEGER,

    FOREIGN KEY (pow_challenge_id)
        REFERENCES pow_challenges(id)
        ON DELETE SET NULL
);
