"""
حِصْن API Gateway v7.1.0
========================
النظام الجديد: مصادقة، توجيه، سجل تدقيق مركزي، معالجة أخطاء موحدة،
وأول خدمة أعمال: تقييم AML باستخدام محرك القواعد.
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
import numpy as np
from sklearn.ensemble import IsolationForest
from app.core.rules_engine import RulesEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("hisn-gateway")

app = FastAPI(title="Hisn Platform Gateway", version="7.1.0")

DB_POOL = None

# -------------------------------
# محرك القواعد + ذكاء اصطناعي بسيط
# -------------------------------
aml_rules_engine = RulesEngine()
anomaly_model = IsolationForest(contamination=0.1, random_state=42)
# تدريب افتراضي (يمكن تحسينه لاحقاً)
X_train = np.random.normal(50000, 20000, 1000).reshape(-1, 1)
anomaly_model.fit(X_train)

# -------------------------------
# إدارة قاعدة البيانات
# -------------------------------
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

# -------------------------------
# المصادقة
# -------------------------------
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

# -------------------------------
# سجل التدقيق
# -------------------------------
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

# -------------------------------
# معالج الأخطاء العام
# -------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"خطأ غير معالج: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "حدث خطأ داخلي في الخادم"}
    )

# -------------------------------
# أحداث بدء التشغيل والإغلاق
# -------------------------------
@app.on_event("startup")
async def startup():
    await get_db_pool()
    await init_db()
    await audit_log("system_startup", "system", "Gateway v7.1.0 started with AML Service")

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
            CREATE TABLE IF NOT EXISTS hisn.aml_transactions (
                id SERIAL PRIMARY KEY,
                customer_id VARCHAR(255),
                amount DECIMAL(15,2),
                currency VARCHAR(10),
                country VARCHAR(5),
                transaction_type VARCHAR(50),
                recipient_id VARCHAR(255),
                invoice_number VARCHAR(255),
                entity_name VARCHAR(255),
                timestamp TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS hisn.account_profiles (
                account_id VARCHAR(255) PRIMARY KEY,
                customer_id VARCHAR(255),
                account_type VARCHAR(50),
                risk_score DECIMAL(5,2) DEFAULT 0.0,
                is_high_risk BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
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
        # بيانات أولية
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
    logger.info("✅ قاعدة البيانات جاهزة (جداول AML إضافية)")

# -------------------------------
# نماذج AML
# -------------------------------
HIGH_RISK_COUNTRIES = {"IR", "KP", "SY", "AF", "MM"}
UNLICENSED_ENTITIES = {"صرافة غير مرخصة", "كيان وهمي", "شركة غير مسجلة"}

class AMLRequest(BaseModel):
    customer_id: str
    amount: float
    currency: str = "SAR"
    country: str
    transaction_type: str
    recipient_id: Optional[str] = None
    invoice_number: Optional[str] = None
    entity_name: Optional[str] = None
    timestamp: Optional[str] = None

class AMLRiskAssessment(BaseModel):
    risk_score: float
    risk_level: str
    triggered_rules: List[str] = []

# -------------------------------
# نقاط النهاية
# -------------------------------
@app.get("/health")
async def health():
    return {"status": "ok", "version": "7.1.0"}

@app.get("/secure/test")
async def secure_test(tenant: dict = Depends(verify_api_key)):
    return {"message": f"مرحباً {tenant['tenant_name']}، المصادقة ناجحة!"}

@app.post("/aml/evaluate", response_model=AMLRiskAssessment)
async def evaluate_aml(request: AMLRequest, tenant: dict = Depends(verify_api_key)):
    """
    تقييم مخاطر غسل الأموال باستخدام:
    - محرك القواعد (4 قواعد أساسية)
    - قواعد متقدمة (دائرية، طبقات، تجارية، كيانات غير مرخصة، حساب عالي المخاطر)
    - كشف شذوذ باستخدام Isolation Forest
    """
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        risk_score = 0.0
        triggered = []
        ref_time = datetime.fromisoformat(request.timestamp) if request.timestamp else datetime.utcnow()

        # 1. استعلامات قاعدة البيانات المطلوبة للسياق
        window_10min = ref_time - timedelta(minutes=10)
        tx_count_10min = await conn.fetchval(
            "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = $1 AND timestamp >= $2",
            request.customer_id, window_10min
        )

        similar_deposits_24h = 0
        if request.transaction_type == "deposit" and 40000 <= request.amount < 50000:
            day_start = ref_time - timedelta(hours=24)
            similar_deposits_24h = await conn.fetchval(
                "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = $1 AND transaction_type='deposit' AND amount >= 40000 AND amount < 50000 AND timestamp >= $2",
                request.customer_id, day_start
            )

        # 2. تقييم محرك القواعد
        context = {
            'amount': request.amount,
            'country': request.country,
            'tx_count_10min': tx_count_10min,
            'similar_deposits_24h': similar_deposits_24h
        }
        engine_triggered, engine_score = aml_rules_engine.evaluate(context)
        triggered.extend(engine_triggered)
        risk_score += engine_score

        # 3. قواعد متقدمة (لن ندخلها في YAML الآن لأنها تحتاج منطق قاعدة بيانات معقد)
        # - التعاملات الدائرية
        if request.recipient_id:
            exists = await conn.fetchval(
                "SELECT id FROM hisn.aml_transactions WHERE customer_id = $1 AND recipient_id = $2 LIMIT 1",
                request.recipient_id, request.customer_id
            )
            if exists:
                triggered.append("circular_transaction")
                risk_score += 0.6

        # - طبقات (layering)
        if request.recipient_id:
            recent_recipient_tx = await conn.fetchval(
                "SELECT COUNT(*) FROM hisn.aml_transactions WHERE customer_id = $1 AND timestamp >= $2",
                request.recipient_id, ref_time - timedelta(minutes=30)
            )
            if recent_recipient_tx > 0:
                triggered.append("layering_detected")
                risk_score += 0.4

        # - غسل أموال تجاري
        if request.invoice_number:
            inv_exists = await conn.fetchval(
                "SELECT id FROM hisn.aml_transactions WHERE invoice_number = $1",
                request.invoice_number
            )
            if inv_exists and request.amount > 100000:
                triggered.append("possible_trade_based_ml")
                risk_score += 0.7

        # - كيان غير مرخص
        if request.entity_name and request.entity_name in UNLICENSED_ENTITIES:
            triggered.append("unlicensed_entity")
            risk_score += 0.8

        # - حساب عالي المخاطر
        account_risk = await conn.fetchval(
            "SELECT risk_score FROM hisn.account_profiles WHERE customer_id = $1",
            request.customer_id
        )
        if account_risk and account_risk > 0.6:
            triggered.append("high_risk_account")
            risk_score += 0.5

        # - كشف الشذوذ بالذكاء الاصطناعي
        amount_np = np.array([[request.amount]])
        if anomaly_model.predict(amount_np)[0] == -1:
            triggered.append("ml_anomaly_amount")
            risk_score += 0.3

        # تسجيل المعاملة في السجل
        await conn.execute(
            "INSERT INTO hisn.aml_transactions (customer_id, amount, currency, country, transaction_type, recipient_id, invoice_number, entity_name, timestamp) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            request.customer_id, request.amount, request.currency, request.country.upper(),
            request.transaction_type, request.recipient_id, request.invoice_number,
            request.entity_name, ref_time
        )

    risk_score = min(risk_score, 1.0)
    risk_level = "high" if risk_score >= 0.7 else "medium" if risk_score >= 0.4 else "low"
    await audit_log("aml_evaluate", "system", f"Customer: {request.customer_id}, Score: {risk_score}, Level: {risk_level}", tenant["tenant_id"])
    return AMLRiskAssessment(risk_score=round(risk_score, 2), risk_level=risk_level, triggered_rules=triggered)
