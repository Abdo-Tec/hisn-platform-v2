"""
حِصْن API Gateway v7.0.0
========================
النظام الجديد: مصادقة، توجيه، سجل تدقيق مركزي، معالجة أخطاء موحدة.
"""

from fastapi import FastAPI, Header, HTTPException, Query, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import asyncpg
import os
import logging
from datetime import datetime, timedelta
import uuid

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("hisn-gateway")

app = FastAPI(title="Hisn Platform Gateway", version="7.0.0")

DB_POOL = None

async def get_db_pool():
    global DB_POOL
    if DB_POOL is None:
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL غير موجود")
        DB_POOL = await asyncpg.create_pool(
            db_url,
            min_size=2,
            max_size=10,
            command_timeout=10
        )
        logger.info("✅ تم إنشاء تجمع اتصالات قاعدة البيانات")
    return DB_POOL

async def close_db_pool():
    global DB_POOL
    if DB_POOL:
        await DB_POOL.close()
        logger.info("🔒 تم إغلاق تجمع اتصالات قاعدة البيانات")

async def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API Key مطلوب في الترويسة X-API-Key")
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name FROM hisn.tenants WHERE api_key = $1", x_api_key
        )
    if not row:
        raise HTTPException(status_code=403, detail="API Key غير صالح")
    return {"tenant_id": str(row["id"]), "tenant_name": row["name"]}

async def audit_log(action: str, user: str = "system", details: str = "", tenant_id: str = "default"):
    try:
        pool = await get_db_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO hisn.audit_trail (action, user_id, details, tenant_id) VALUES ($1, $2, $3, $4)",
                action, user, details, tenant_id
            )
    except Exception as e:
        logger.error(f"فشل سجل التدقيق: {e}")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"خطأ غير معالج: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "حدث خطأ داخلي في الخادم"}
    )

@app.on_event("startup")
async def startup():
    await get_db_pool()
    await init_db()
    await audit_log("system_startup", "system", "Gateway v7.0 started")

@app.on_event("shutdown")
async def shutdown():
    await close_db_pool()

async def init_db():
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        await conn.execute("CREATE SCHEMA IF NOT EXISTS hisn")
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS hisn.tenants (
                id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                api_key VARCHAR(64) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.watchlist (
                id SERIAL PRIMARY KEY,
                full_name_ar VARCHAR(500),
                full_name_en VARCHAR(500),
                list_type VARCHAR(50),
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.audit_trail (
                id SERIAL PRIMARY KEY,
                action VARCHAR(255),
                user_id VARCHAR(255) DEFAULT 'system',
                details TEXT,
                tenant_id VARCHAR(255) DEFAULT 'default',
                created_at TIMESTAMP DEFAULT NOW()
            );
        """)
        existing = await conn.fetchval("SELECT COUNT(*) FROM hisn.watchlist")
        if existing == 0:
            await conn.execute("""
                INSERT INTO hisn.watchlist (full_name_ar, full_name_en, list_type) VALUES
                ('أسامة بن لادن', 'Osama bin Laden', 'UN'),
                ('أيمن الظواهري', 'Ayman al-Zawahiri', 'UN'),
                ('أبو بكر البغدادي', 'Abu Bakr al-Baghdadi', 'UN'),
                ('قاسم الريمي', 'Qasim al-Raymi', 'UN')
            """)
        tenant_exists = await conn.fetchval("SELECT COUNT(*) FROM hisn.tenants WHERE api_key = $1", "dev-api-key-12345")
        if tenant_exists == 0:
            await conn.execute("INSERT INTO hisn.tenants (name, api_key) VALUES ($1, $2)", "Default Tenant", "dev-api-key-12345")
    logger.info("✅ قاعدة البيانات جاهزة")

@app.get("/health")
async def health():
    return {"status": "ok", "version": "7.0.0"}

@app.get("/secure/test")
async def secure_test(tenant: dict = Depends(verify_api_key)):
    return {"message": f"مرحباً {tenant['tenant_name']}، المصادقة ناجحة!"}
