async fn init_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite:fantasma0.db").await.unwrap();

    sqlx::query("PRAGMA journal_mode=WAL;").execute(&pool).await.unwrap();
    sqlx::query("PRAGMA synchronous=NORMAL;").execute(&pool).await.unwrap();
    sqlx::query("PRAGMA temp_store=MEMORY;").execute(&pool).await.unwrap();

    pool
}
