"""Hardened API Heist Academy service.

The original classroom release intentionally implemented the OWASP API Top 10.
This edition keeps the API surface for defensive verification while enforcing
authentication, authorization, validation, and safe outbound integrations.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DVAPI_DB", BASE_DIR / "heist.db"))
STATIC_DIR = BASE_DIR.parent / "frontend"
HOST = os.environ.get("DVAPI_HOST", "127.0.0.1")
PORT = int(os.environ.get("DVAPI_PORT", "5000"))

JWT_ISSUER = "api-heist-academy"
JWT_AUDIENCE = "api-heist-api"
TOKEN_TTL_SECONDS = int(os.environ.get("DVAPI_TOKEN_TTL_SECONDS", "7200"))
MAX_JSON_BYTES = int(os.environ.get("DVAPI_MAX_JSON_BYTES", "16384"))
RATE_LIMIT = int(os.environ.get("DVAPI_RATE_LIMIT", "5"))
RATE_WINDOW_SECONDS = int(os.environ.get("DVAPI_RATE_WINDOW_SECONDS", "60"))
REGISTRATION_LIMIT = int(os.environ.get("DVAPI_REGISTRATION_LIMIT", "20"))
REGISTRATION_WINDOW_SECONDS = int(os.environ.get("DVAPI_REGISTRATION_WINDOW_SECONDS", "3600"))
TRANSFER_LIMIT_PER_WINDOW = int(os.environ.get("DVAPI_TRANSFER_LIMIT", "10"))
TRANSFER_WINDOW_SECONDS = int(os.environ.get("DVAPI_TRANSFER_WINDOW_SECONDS", "60"))
TRANSFER_MAX_AMOUNT = int(os.environ.get("DVAPI_TRANSFER_MAX_AMOUNT", "100"))
TRANSFER_MAX_WINDOW_AMOUNT = int(os.environ.get("DVAPI_TRANSFER_MAX_WINDOW_AMOUNT", "500"))
WEBHOOK_MAX_AGE_SECONDS = int(os.environ.get("DVAPI_WEBHOOK_MAX_AGE_SECONDS", "300"))
FETCH_MAX_BYTES = int(os.environ.get("DVAPI_FETCH_MAX_BYTES", "8192"))
FETCH_ALLOWLIST = {
    host.strip().lower().rstrip(".")
    for host in os.environ.get("DVAPI_FETCH_ALLOWLIST", "").split(",")
    if host.strip()
}


def _configured_secret(name: str, *, required_for_remote: bool = False) -> str | None:
    value = os.environ.get(name)
    if value and len(value) < 32:
        raise RuntimeError(f"{name} must contain at least 32 characters")
    if required_for_remote and HOST not in {"127.0.0.1", "localhost", "::1"} and not value:
        raise RuntimeError(f"{name} is required when DVAPI_HOST is not loopback")
    return value


# A random local-only signing key is safer than a checked-in default. Remote
# deployments must provide a stable high-entropy secret explicitly.
SECRET = _configured_secret("DVAPI_SECRET", required_for_remote=True) or secrets.token_urlsafe(48)
ADMIN_TOKEN = _configured_secret("DVAPI_ADMIN_TOKEN")
WEBHOOK_SECRET = _configured_secret("DVAPI_WEBHOOK_SECRET")

CHALLENGES = {
    1: {
        "slug": "bola",
        "title": "Broken Object Level Authorization (BOLA)",
        "codename": "The Locker Room",
        "icon": "",
        "points": 15,
        "endpoint": "GET /api/user/{id}",
        "description": (
            "Authenticated teams may view only the profile bound to their signed token. "
            "Other object identifiers are denied."
        ),
        "objective": "Verify that cross-object requests receive HTTP 403.",
        "hints": [
            "Use the Bearer token returned during team registration.",
            "The token subject and requested object must match.",
        ],
    },
    2: {
        "slug": "broken-auth",
        "title": "Broken Authentication",
        "codename": "The Guard Post",
        "icon": "",
        "points": 15,
        "endpoint": "GET /api/admin",
        "description": (
            "Administrative routes use a dedicated high-entropy credential and reject "
            "unsigned, forged, or expired team tokens."
        ),
        "objective": "Verify that forged JWTs and team tokens cannot reach admin functions.",
        "hints": [
            "JWT signatures, issuer, audience, timestamps, and token type are validated.",
            "Admin actions require X-Admin-Token and are disabled when it is not configured.",
        ],
    },
    3: {
        "slug": "mass-assignment",
        "title": "Mass Assignment",
        "codename": "Property Tycoon",
        "icon": "",
        "points": 15,
        "endpoint": "PUT /api/user/update",
        "description": (
            "Profile updates accept only the explicitly editable name and email properties. "
            "Server-owned fields remain immutable."
        ),
        "objective": "Verify that role, balance, and unknown fields are rejected.",
        "hints": [
            "Update endpoints sometimes honor fields you never see in the UI.",
            "Think about properties that change who you are — not just your name or email.",
        ],
    },
    4: {
        "slug": "resource-consumption",
        "title": "Unrestricted Resource Consumption",
        "codename": "Flood Gate",
        "icon": "",
        "points": 15,
        "endpoint": "GET /api/rate-limited",
        "description": (
            "This endpoint applies a hard per-team request limit with a fixed time window "
            "and a Retry-After response."
        ),
        "objective": "Verify that excess requests remain blocked with HTTP 429.",
        "hints": [
            "Watch how the response changes as traffic increases.",
            "Soft limits and hard limits behave differently when you keep going.",
        ],
    },
    5: {
        "slug": "bfla",
        "title": "Broken Function Level Authorization",
        "codename": "The Back Door",
        "icon": "",
        "points": 15,
        "endpoint": "DELETE /api/admin/users",
        "description": (
            "Administrative functions enforce a centralized administrator check before "
            "executing route logic."
        ),
        "objective": "Verify that unauthenticated and team-level callers are rejected.",
        "hints": [
            "Naming and HTTP methods can hint at who a route was built for.",
            "Absence of an error is sometimes the vulnerability.",
        ],
    },
    6: {
        "slug": "business-flow",
        "title": "Unrestricted Access to Sensitive Business Flows",
        "codename": "Money Printer",
        "icon": "",
        "points": 15,
        "endpoint": "POST /api/transfer",
        "description": (
            "Transfers enforce amount, balance, velocity, cumulative-value, and "
            "idempotency controls inside a database transaction."
        ),
        "objective": "Verify invalid, duplicate, and excessive transfers are safely handled.",
        "hints": [
            "One request is allowed. What about many?",
            "Automation turns a tiny action into a large effect.",
        ],
    },
    7: {
        "slug": "ssrf",
        "title": "Server Side Request Forgery (SSRF)",
        "codename": "The Messenger",
        "icon": "",
        "points": 15,
        "endpoint": "POST /api/fetch-url",
        "description": (
            "Outbound fetches are default-deny, HTTPS-only, allowlisted, redirect-free, "
            "size-limited, and restricted to public IP addresses."
        ),
        "objective": "Verify that loopback, link-local, private, and unlisted destinations are denied.",
        "hints": [
            "The interesting destinations are often not on the public internet.",
            "Cloud environments and loopback addresses are classic places to probe carefully.",
        ],
    },
    8: {
        "slug": "misconfig",
        "title": "Security Misconfiguration",
        "codename": "Debug Dump",
        "icon": "",
        "points": 15,
        "endpoint": "GET /api/debug",
        "description": (
            "Debug routes and verbose exception payloads are disabled. API errors are "
            "generic and security headers are applied centrally."
        ),
        "objective": "Verify that debug probes return HTTP 404 without stack traces.",
        "hints": [
            "Healthy endpoints sometimes still accept unusual query options.",
            "Error pages and stack traces are part of the attack surface.",
        ],
    },
    9: {
        "slug": "inventory",
        "title": "Improper Inventory Management",
        "codename": "Shadow API",
        "icon": "",
        "points": 15,
        "endpoint": "GET /api/v2/users",
        "description": (
            "The deprecated v1 surface is retired with HTTP 410 and successor metadata. "
            "The current v2 route is authenticated and data-minimized."
        ),
        "objective": "Verify that v1 exposes no records and v2 returns only the caller's object.",
        "hints": [
            "Version numbers in paths often leave breadcrumbs.",
            "What shipped before the current version may still be listening.",
        ],
    },
    10: {
        "slug": "unsafe-consumption",
        "title": "Unsafe Consumption of APIs",
        "codename": "Webhook Trap",
        "icon": "",
        "points": 15,
        "endpoint": "POST /api/webhook",
        "description": (
            "Inbound webhooks require an HMAC signature, a fresh timestamp, an allowlisted "
            "event type, bounded JSON, and replay protection."
        ),
        "objective": "Verify that unsigned, stale, replayed, and unsupported events are rejected.",
        "hints": [
            "Treat every field as untrusted — including ones that look like control signals.",
            "Special names and template-like strings are worth experimenting with.",
        ],
    },
}

# This content powers the post-remediation learning view. It describes safe
# negative tests and their blocked responses instead of restoring flags.
HARDENING_GUIDE = {
    1: {
        "risk_before": "كان العميل يستطيع تغيير رقم المستخدم في المسار وقراءة كائن لا يملكه، لأن الخادم اعتمد على المعرّف القادم من الطلب دون ربطه بهوية موثقة.",
        "root_cause": "غياب التحقق من ملكية الكائن بعد المصادقة (Object ownership check).",
        "controls": [
            "كل طلب محمي يتطلب Bearer token صالحًا وموقعًا من الخادم.",
            "هوية الفريق ورقم الملف يؤخذان من الرمز، ويُرفض أي معرّف مختلف بالحالة 403.",
            "الاستجابة تعرض حقول الملف العامة فقط ولا تكشف الحقول الحساسة.",
        ],
        "code_changes": [
            "authenticate_team() يتحقق من التوقيع وissuer وaudience والصلاحية والnonce.",
            "require_team يضع الفريق الموثق في g.current_team قبل تنفيذ المسار.",
            "get_user() يقارن user_id مع معرف الفريق الموثق قبل جلب البيانات.",
        ],
        "tests": [
            {"name": "قراءة الملف المملوك", "request": "GET /api/user/<profileId>\nAuthorization: Bearer <accessToken>", "expected": "HTTP 200، ويطابق user.id قيمة profileId."},
            {"name": "محاولة BOLA", "request": "GET /api/user/<anotherProfileId>\nAuthorization: Bearer <accessToken>", "expected": "HTTP 403 مع Object access denied، دون بيانات المستخدم الآخر."},
            {"name": "طلب بلا مصادقة", "request": "GET /api/user/<profileId>", "expected": "HTTP 401."},
        ],
    },
    2: {
        "risk_before": "كانت آلية المصادقة تسمح بالاعتماد على بيانات يمكن تزويرها أو إعادة استخدامها، وقد تختلط صلاحيات الفريق مع صلاحيات المدير.",
        "root_cause": "تحقق غير مكتمل من الرمز وعدم فصل اعتماد المدير عن اعتماد المستخدم.",
        "controls": [
            "JWT قصير العمر وموقع بسر قوي مع issuer وaudience وiat وnbf وexp.",
            "nonce عشوائي مخزن للفريق يمنع قبول رمز قديم بعد تدوير الاعتماد.",
            "عمليات المدير تستخدم X-Admin-Token منفصلًا ولا تقبل رمز الفريق.",
        ],
        "code_changes": [
            "issue_team_token() يصدر claims محددة بزمن ونوع وهوية واضحة.",
            "authenticate_team() يقيد الخوارزمية إلى HS256 ويتحقق من جميع claims المطلوبة.",
            "require_admin() يستخدم مقارنة ثابتة الزمن ويعطل الإدارة إن لم يضبط السر.",
        ],
        "tests": [
            {"name": "رمز فريق صحيح", "request": "GET /api/user/<profileId>\nAuthorization: Bearer <accessToken>", "expected": "HTTP 200 للملف المملوك فقط."},
            {"name": "JWT مزور أو منتهي", "request": "GET /api/user/<profileId>\nAuthorization: Bearer <forged-or-expired-token>", "expected": "HTTP 401 دون تفاصيل عن سبب فشل التوقيع."},
            {"name": "رمز فريق على مسار مدير", "request": "GET /api/admin\nAuthorization: Bearer <accessToken>", "expected": "HTTP 401؛ يلزم X-Admin-Token المنفصل."},
        ],
    },
    3: {
        "risk_before": "كان تحديث الملف قد يمرر الخصائص القادمة من JSON مباشرة إلى نموذج المستخدم، ما يسمح بتعديل role أو balance وخصائص غير معروضة في الواجهة.",
        "root_cause": "ربط جماعي للمدخلات دون قائمة سماح للحقول القابلة للتحرير.",
        "controls": [
            "المسموح فقط name وemail.",
            "أي حقل مجهول أو مملوك للخادم يرفض الطلب كاملًا بالحالة 400.",
            "تطبق حدود نوع وطول وصيغة على القيم المقبولة.",
        ],
        "code_changes": [
            "update_user() يقارن مفاتيح JSON مع allowed_fields قبل تنفيذ SQL.",
            "الاستعلام يحدد الأعمدة القابلة للتعديل صراحة بدل بناء استعلام من مدخلات العميل.",
            "الهوية المستهدفة تأتي من g.current_team لا من جسم الطلب.",
        ],
        "tests": [
            {"name": "تعديل مسموح", "request": "PUT /api/user/update\nAuthorization: Bearer <accessToken>\n\n{\"name\":\"New Name\",\"email\":\"new@example.test\"}", "expected": "HTTP 200 مع بقاء role=user وbalance دون تغيير."},
            {"name": "Mass assignment", "request": "PUT /api/user/update\nAuthorization: Bearer <accessToken>\n\n{\"role\":\"admin\",\"balance\":999999}", "expected": "HTTP 400 ويعرض أسماء الحقول المرفوضة فقط."},
        ],
    },
    4: {
        "risk_before": "كان بالإمكان تكرار الطلبات بكثافة دون حد صلب، مما يستهلك موارد الخدمة ويؤثر في توافرها.",
        "root_cause": "غياب حد طلبات ذري مرتبط بهوية موثقة ونافذة زمنية واضحة.",
        "controls": [
            "حد ثابت لكل فريق داخل نافذة زمنية.",
            "التحديث داخل BEGIN IMMEDIATE لمنع تجاوز الحد عبر الطلبات المتزامنة.",
            "الطلبات الزائدة تبقى 429 وتحتوي Retry-After.",
        ],
        "code_changes": [
            "rate_limited() يستخدم جدول rate_limits بدل عداد في الذاكرة.",
            "المفتاح مرتبط بالفريق الموثق وليس بهيدر يختاره العميل.",
            "لا توجد استجابة نجاح أو flag بعد بلوغ الحد.",
        ],
        "tests": [
            {"name": "اختبار الحد الصلب", "request": "أرسل GET /api/rate-limited ثماني مرات بنفس Bearer token.", "expected": "أول 5 طلبات HTTP 200، ثم كل الطلبات الزائدة HTTP 429 مع Retry-After."},
        ],
    },
    5: {
        "risk_before": "كان مجرد معرفة مسار إداري أو استخدام DELETE قد يسمح لمستخدم عادي بتنفيذ وظيفة أعلى من مستوى صلاحيته.",
        "root_cause": "عدم تطبيق تفويض وظيفي مركزي على المسارات الإدارية.",
        "controls": [
            "كل وظيفة إدارية محاطة بـ require_admin.",
            "رمز الفريق لا يمنح صلاحية إدارية حتى لو حمل claim مزورة.",
            "اعتماد المدير منفصل وعالي العشوائية ويقارن ثابت الزمن.",
        ],
        "code_changes": [
            "require_admin() أصبح بوابة موحدة قبل منطق المسار.",
            "delete_users() وadmin_panel() لا ينفذان قبل نجاح X-Admin-Token.",
            "تعطّل الوظائف الإدارية بالحالة 503 إن لم يضبط اعتماد المدير.",
        ],
        "tests": [
            {"name": "بلا اعتماد مدير", "request": "DELETE /api/admin/users", "expected": "HTTP 401 ولا يحذف أي مستخدم."},
            {"name": "باستخدام رمز فريق", "request": "DELETE /api/admin/users\nAuthorization: Bearer <accessToken>", "expected": "HTTP 401؛ Bearer token لا يعادل X-Admin-Token."},
        ],
    },
    6: {
        "risk_before": "كان تدفق التحويل يقبل مبالغ سالبة أو تكرارًا آليًا أو إعادة إرسال الطلب، مما يسمح بتغيير الرصيد خارج قواعد العمل.",
        "root_cause": "التحقق من الطلب منفردًا دون ضوابط قيمة وتكرار وسرعة ومعاملة ذرية.",
        "controls": [
            "المبلغ عدد صحيح موجب لا يتجاوز الحد وبوجود رصيد كافٍ.",
            "Idempotency-Key إلزامي ويمنع تنفيذ الطلب نفسه مرتين.",
            "حد لعدد التحويلات ومجموع قيمتها داخل النافذة الزمنية.",
        ],
        "code_changes": [
            "transfer() ينفذ التحقق والخصم والتسجيل داخل معاملة BEGIN IMMEDIATE.",
            "جدول transfer_idempotency يحفظ نتيجة المفتاح ويعيدها دون خصم جديد.",
            "جدول transfers يتيح حساب السرعة والقيمة التراكمية قبل التنفيذ.",
        ],
        "tests": [
            {"name": "مبلغ غير صالح", "request": "POST /api/transfer\nAuthorization: Bearer <accessToken>\nIdempotency-Key: negative-1\n\n{\"to\":\"Bob\",\"amount\":-10}", "expected": "HTTP 400 دون تغيير الرصيد."},
            {"name": "إعادة نفس الطلب", "request": "أرسل تحويلًا صالحًا مرتين بنفس Idempotency-Key.", "expected": "HTTP 200 للمرتين، والثانية idempotent_replay=true دون خصم جديد."},
            {"name": "تجاوز القيمة التراكمية", "request": "أرسل تحويلات صالحة بمفاتيح مختلفة حتى تتجاوز حد النافذة.", "expected": "HTTP 429 عند تجاوز الحد."},
        ],
    },
    7: {
        "risk_before": "كان الخادم يجلب أي URL يرسله العميل، بما في ذلك loopback أو العناوين الخاصة وخدمة metadata السحابية.",
        "root_cause": "جلب URL غير موثوق دون سياسة وجهات أو تحقق DNS أو منع التحويلات.",
        "controls": [
            "السياسة Default-deny وتسمح فقط بـ HTTPS ومضيف موجود حرفيًا في allowlist.",
            "كل عناوين DNS يجب أن تكون عامة؛ تحظر private وloopback وlink-local وغيرها.",
            "التحويلات ممنوعة وحجم الاستجابة والمهلة محدودان.",
        ],
        "code_changes": [
            "fetch_host_is_allowed() يطبق مطابقة مضيف دقيقة بدل substring.",
            "host_resolves_publicly() يفحص جميع نتائج DNS باستخدام ipaddress.",
            "fetch_url() يعطل redirects ويقيد scheme والمنفذ والحجم والمهلة.",
        ],
        "tests": [
            {"name": "خدمة metadata", "request": "POST /api/fetch-url\nAuthorization: Bearer <accessToken>\n\n{\"url\":\"http://169.254.169.254/latest/meta-data/\"}", "expected": "HTTP 400 قبل أي اتصال خارجي."},
            {"name": "مضيف HTTPS غير مسموح", "request": "POST /api/fetch-url\nAuthorization: Bearer <accessToken>\n\n{\"url\":\"https://example.com\"}", "expected": "HTTP 403 عندما لا يكون المضيف ضمن DVAPI_FETCH_ALLOWLIST."},
        ],
    },
    8: {
        "risk_before": "كانت مسارات التصحيح ورسائل الخطأ قد تكشف stack trace أو إعدادات وأسرار، كما قد تغيب ترويسات الحماية الأساسية.",
        "root_cause": "إبقاء أدوات التطوير ورسائل الأخطاء التفصيلية ضمن سطح الإنتاج.",
        "controls": [
            "مسار /api/debug غير موجود والاستثناءات غير المتوقعة تعاد برسالة عامة.",
            "CSP وX-Frame-Options وnosniff وسياسات cache/referrer تطبق مركزيًا.",
            "CORS غير مفتوح افتراضيًا ولا توجد أسرار ثابتة داخل المصدر.",
        ],
        "code_changes": [
            "debug_endpoint() يعيد 404 دون معلومات داخلية.",
            "handle_unexpected_error() لا يرسل تفاصيل الاستثناء للعميل.",
            "security_headers() يضيف ترويسات الدفاع لكل استجابة.",
        ],
        "tests": [
            {"name": "فحص debug", "request": "GET /api/debug?crash=1", "expected": "HTTP 404؛ لا traceback ولا flag ولا أسرار."},
            {"name": "فحص الترويسات", "request": "GET /health", "expected": "توجد CSP وX-Frame-Options: DENY وX-Content-Type-Options: nosniff."},
        ],
    },
    9: {
        "risk_before": "كانت نسخة API قديمة تظل متاحة وتعرض بيانات أكثر من النسخة الحالية، فتصبح واجهة ظل يمكن تجاوز الضوابط عبرها.",
        "root_cause": "غياب جرد وإيقاف واضح للإصدارات القديمة مع اختلاف ضوابط الوصول.",
        "controls": [
            "الإصدار v1 متقاعد ويرد 410 دون سجلات.",
            "الإصدار v2 يتطلب Bearer token ويعيد سجل المتصل فقط.",
            "ترويسات Deprecation وLink توضح الإصدار البديل دون إبقاء الوظيفة القديمة.",
        ],
        "code_changes": [
            "users_v1() يعيد 410 وبيانات انتقال فقط.",
            "users_v2() محمي بـ require_team ويقلل الحقول إلى id وname.",
            "لا يوجد مسار قديم بديل يعيد قائمة المستخدمين.",
        ],
        "tests": [
            {"name": "الإصدار المتقاعد", "request": "GET /api/v1/users", "expected": "HTTP 410 مع Deprecation: true ودون مصفوفة users."},
            {"name": "الإصدار الحالي", "request": "GET /api/v2/users\nAuthorization: Bearer <accessToken>", "expected": "HTTP 200 وسجل واحد للمتصل؛ وHTTP 401 دون الرمز."},
        ],
    },
    10: {
        "risk_before": "كان webhook يثق في JSON القادم من خدمة خارجية دون إثبات المصدر أو الحداثة، ما يسمح بحقن أحداث أو إعادة الطلب المقبول.",
        "root_cause": "استهلاك بيانات طرف ثالث كأنها موثوقة دون توقيع ومخطط ومنع replay.",
        "controls": [
            "HMAC-SHA256 على timestamp والنص الخام للجسم باستخدام سر مشترك.",
            "نافذة زمنية قصيرة ونوع حدث allowlisted وحجم JSON محدود.",
            "بصمة التوقيع تخزن لمنع إعادة نفس الرسالة.",
        ],
        "code_changes": [
            "webhook() يتحقق من X-Webhook-Timestamp وX-Webhook-Signature قبل معالجة JSON.",
            "hmac.compare_digest يمنع مقارنة توقيع غير آمنة.",
            "جدول webhook_replays يسجل البصمة داخل معاملة ويعيد 409 عند التكرار.",
        ],
        "tests": [
            {"name": "Webhook بلا توقيع", "request": "POST /api/webhook\nContent-Type: application/json\n\n{\"event\":\"ping\",\"payload\":\"hello\"}", "expected": "HTTP 401."},
            {"name": "Webhook صحيح", "request": "احسب HMAC على <timestamp>.<raw-body> وأرسل الترويسات المطلوبة.", "expected": "HTTP 202 للمرة الأولى، ثم HTTP 409 عند إعادة الرسالة نفسها."},
        ],
    },
}

DEMO_USERS = [
    {"id": 1, "name": "Alice", "email": "alice@heist.local", "role": "user", "balance": 100},
    {"id": 2, "name": "Bob", "email": "bob@heist.local", "role": "user", "balance": 250},
    {
        "id": 3,
        "name": "Carol",
        "email": "carol@heist.local",
        "role": "user",
        "balance": 999,
    },
    {"id": 4, "name": "Dave", "email": "dave@heist.local", "role": "user", "balance": 40},
]

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_JSON_BYTES


def api_error(message: str, status: int, **extra: Any):
    payload = {"error": message}
    payload.update(extra)
    response = jsonify(payload)
    if status == 401:
        response.headers["WWW-Authenticate"] = 'Bearer realm="api-heist"'
    return response, status


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def issue_team_token(team: sqlite3.Row) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": f"team:{team['id']}",
        "team_id": int(team["id"]),
        "team": team["name"],
        "user_id": int(team["id"]),
        "role": "team",
        "nonce": team["auth_nonce"],
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=TOKEN_TTL_SECONDS),
    }
    return jwt.encode(claims, SECRET, algorithm="HS256")


def authenticate_team() -> tuple[sqlite3.Row | None, Any | None]:
    token = _bearer_token()
    if not token:
        return None, api_error("Authentication required", 401)
    try:
        claims = jwt.decode(
            token,
            SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            leeway=5,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
        )
        team_id = int(claims.get("team_id"))
    except (jwt.InvalidTokenError, TypeError, ValueError):
        return None, api_error("Invalid or expired access token", 401)

    if claims.get("role") != "team" or claims.get("sub") != f"team:{team_id}":
        return None, api_error("Invalid or expired access token", 401)
    team = get_db().execute("SELECT * FROM teams WHERE id = ?", (team_id,)).fetchone()
    nonce = str(claims.get("nonce") or "")
    if (
        not team
        or claims.get("team") != team["name"]
        or not nonce
        or not hmac.compare_digest(nonce, str(team["auth_nonce"] or ""))
    ):
        return None, api_error("Invalid or expired access token", 401)
    g.auth_claims = claims
    return team, None


def require_team(view):
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        team, error = authenticate_team()
        if error:
            return error
        g.current_team = team
        return view(*args, **kwargs)

    return wrapped


def authenticate_admin() -> Any | None:
    if not ADMIN_TOKEN:
        return api_error("Admin operations are disabled until DVAPI_ADMIN_TOKEN is configured", 503)
    supplied = request.headers.get("X-Admin-Token", "")
    if not supplied or not hmac.compare_digest(supplied, ADMIN_TOKEN):
        return api_error("Administrator authentication required", 401)
    return None


def require_admin(view):
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        error = authenticate_admin()
        if error:
            return error
        return view(*args, **kwargs)

    return wrapped


def public_team(team: sqlite3.Row, *, include_members: bool = True) -> dict[str, Any]:
    result = {
        "name": team["name"],
        "points": int(team["points"]),
        "hints_used": int(team["hints_used"]),
        "total_time_seconds": int(team["total_time_seconds"]),
        "assigned_challenge": team["assigned_challenge"],
    }
    if include_members:
        result["members"] = json.loads(team["members"] or "[]")
    return result


def clean_text(value: Any, *, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} is required")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} is too long")
    if any(ord(char) < 32 for char in cleaned):
        raise ValueError(f"{field} contains control characters")
    return cleaned


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_: RequestEntityTooLarge):
    return api_error("Request body too large", 413)


@app.errorhandler(Exception)
def handle_unexpected_error(exc: Exception):
    if isinstance(exc, HTTPException):
        if request.path.startswith("/api/"):
            return api_error(exc.name, exc.code or 500)
        return exc
    app.logger.exception("Unhandled request failure")
    return api_error("Internal server error", 500)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            points INTEGER NOT NULL DEFAULT 0,
            hints_used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            total_time_seconds INTEGER NOT NULL DEFAULT 0,
            members TEXT NOT NULL DEFAULT '[]',
            assigned_challenge INTEGER,
            auth_nonce TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS team_accounts (
            team_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            balance INTEGER NOT NULL DEFAULT 1000,
            FOREIGN KEY(team_id) REFERENCES teams(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS challenge_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            solved INTEGER NOT NULL DEFAULT 0,
            hints_used INTEGER NOT NULL DEFAULT 0,
            requests INTEGER NOT NULL DEFAULT 0,
            time_seconds INTEGER,
            solved_at TEXT,
            points_earned INTEGER NOT NULL DEFAULT 0,
            UNIQUE(team_id, challenge_id),
            FOREIGN KEY(team_id) REFERENCES teams(id)
        );
        CREATE TABLE IF NOT EXISTS session_challenges (
            challenge_id INTEGER PRIMARY KEY,
            solved INTEGER NOT NULL DEFAULT 0,
            solved_by TEXT,
            points_earned INTEGER NOT NULL DEFAULT 0,
            time_seconds INTEGER
        );
        CREATE TABLE IF NOT EXISTS game_session (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            remaining_seconds INTEGER NOT NULL DEFAULT 6000,
            running INTEGER NOT NULL DEFAULT 0,
            ended INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rate_counters (
            team_key TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0,
            window_start REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transfer_counters (
            team_key TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0,
            window_start REAL NOT NULL DEFAULT 0,
            total_amount INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS registration_counters (
            client_key TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0,
            window_start REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_key TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            created_at REAL NOT NULL,
            UNIQUE(team_key, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
            signature TEXT PRIMARY KEY,
            received_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users_demo (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            role TEXT,
            balance INTEGER,
            extra TEXT
        );
        """
    )
    # Lightweight migrations for older DBs
    cols = {r[1] for r in db.execute("PRAGMA table_info(teams)").fetchall()}
    if "members" not in cols:
        db.execute("ALTER TABLE teams ADD COLUMN members TEXT NOT NULL DEFAULT '[]'")
    if "assigned_challenge" not in cols:
        db.execute("ALTER TABLE teams ADD COLUMN assigned_challenge INTEGER")
    if "auth_nonce" not in cols:
        db.execute("ALTER TABLE teams ADD COLUMN auth_nonce TEXT")
    for row in db.execute("SELECT id FROM teams WHERE auth_nonce IS NULL OR auth_nonce = ''").fetchall():
        db.execute(
            "UPDATE teams SET auth_nonce = ? WHERE id = ?",
            (secrets.token_urlsafe(32), row[0]),
        )
    for team_id, team_name in db.execute("SELECT id, name FROM teams").fetchall():
        db.execute(
            """
            INSERT OR IGNORE INTO team_accounts (team_id, name, email, role, balance)
            VALUES (?, ?, ?, 'user', 1000)
            """,
            (team_id, team_name, f"team-{team_id}@heist.local"),
        )

    transfer_cols = {r[1] for r in db.execute("PRAGMA table_info(transfer_counters)").fetchall()}
    if "window_start" not in transfer_cols:
        db.execute("ALTER TABLE transfer_counters ADD COLUMN window_start REAL NOT NULL DEFAULT 0")
    if "total_amount" not in transfer_cols:
        db.execute("ALTER TABLE transfer_counters ADD COLUMN total_amount INTEGER NOT NULL DEFAULT 0")

    if db.execute("SELECT COUNT(*) FROM game_session").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO game_session (id, remaining_seconds, running, ended, updated_at) VALUES (1, 6000, 0, 0, ?)",
            (time.time(),),
        )
    if db.execute("SELECT COUNT(*) FROM session_challenges").fetchone()[0] == 0:
        for cid in range(1, 12):
            db.execute(
                "INSERT INTO session_challenges (challenge_id, solved) VALUES (?, 0)",
                (cid,),
            )
    existing = db.execute("SELECT COUNT(*) FROM users_demo").fetchone()[0]
    if existing == 0:
        for u in DEMO_USERS:
            extra = {k: v for k, v in u.items() if k not in ("id", "name", "email", "role", "balance")}
            db.execute(
                "INSERT INTO users_demo (id, name, email, role, balance, extra) VALUES (?,?,?,?,?,?)",
                (u["id"], u["name"], u["email"], u["role"], u["balance"], json.dumps(extra)),
            )
    db.commit()
    db.close()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


SESSION_DURATION = 100 * 60  # 100 minutes


def ensure_session(db: sqlite3.Connection) -> sqlite3.Row:
    row = db.execute("SELECT * FROM game_session WHERE id = 1").fetchone()
    if not row:
        db.execute(
            "INSERT INTO game_session (id, remaining_seconds, running, ended, updated_at) VALUES (1, ?, 0, 0, ?)",
            (SESSION_DURATION, time.time()),
        )
        db.commit()
        row = db.execute("SELECT * FROM game_session WHERE id = 1").fetchone()
    return row


def read_session(db: sqlite3.Connection) -> dict[str, Any]:
    row = ensure_session(db)
    remaining = int(row["remaining_seconds"])
    running = bool(row["running"])
    ended = bool(row["ended"])
    now = time.time()

    if running and not ended:
        elapsed = now - float(row["updated_at"])
        remaining = max(0, int(remaining - elapsed))
        if remaining <= 0:
            remaining = 0
            ended = True
            running = False
            db.execute(
                "UPDATE game_session SET remaining_seconds = 0, running = 0, ended = 1, updated_at = ? WHERE id = 1",
                (now,),
            )
            db.commit()

    solved_rows = db.execute(
        "SELECT * FROM session_challenges ORDER BY challenge_id"
    ).fetchall()
    challenges = {
        r["challenge_id"]: {
            "solved": bool(r["solved"]),
            "solvedBy": r["solved_by"],
            "pointsEarned": r["points_earned"],
            "time": r["time_seconds"],
        }
        for r in solved_rows
    }
    next_challenge = 1
    for cid in range(1, 11):
        if not challenges.get(cid, {}).get("solved"):
            next_challenge = cid
            break
    else:
        next_challenge = 11 if not challenges.get(11, {}).get("solved") else None

    return {
        "remainingSeconds": remaining,
        "running": running,
        "ended": ended,
        "durationSeconds": SESSION_DURATION,
        "nextChallenge": next_challenge,
        "challenges": challenges,
    }


def persist_remaining(db: sqlite3.Connection, remaining: int, running: bool, ended: bool) -> None:
    db.execute(
        """
        UPDATE game_session
        SET remaining_seconds = ?, running = ?, ended = ?, updated_at = ?
        WHERE id = 1
        """,
        (remaining, 1 if running else 0, 1 if ended else 0, time.time()),
    )
    db.commit()


def require_session_active(db: sqlite3.Connection) -> tuple[dict[str, Any] | None, Any]:
    session = read_session(db)
    if session["ended"] or session["remainingSeconds"] <= 0:
        persist_remaining(db, 0, False, True)
        return None, (jsonify({"error": "Session time is over. The game has stopped.", "session": session}), 403)
    return session, None


def team_key_from_request() -> str:
    team = getattr(g, "current_team", None)
    if not team:
        raise RuntimeError("Authenticated team context required")
    return f"team:{team['id']}"


def ok(message: str, **extra: Any):
    payload = {
        "success": True,
        "message": message,
        "hint_used": False,
    }
    payload.update(extra)
    return jsonify(payload)


def track_request(challenge_id: int) -> None:
    team = getattr(g, "current_team", None)
    if not team:
        return
    db = get_db()
    db.execute(
        """
        INSERT INTO challenge_progress (team_id, challenge_id, requests)
        VALUES (?, ?, 1)
        ON CONFLICT(team_id, challenge_id) DO UPDATE SET requests = requests + 1
        """,
        (team["id"], challenge_id),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Game management API
# ---------------------------------------------------------------------------


@app.get("/api/challenges")
def list_challenges():
    items = []
    for cid, meta in CHALLENGES.items():
        items.append(
            {
                "id": cid,
                "title": meta["title"],
                "codename": meta["codename"],
                "icon": meta["icon"],
                "points": meta["points"],
                "endpoint": meta["endpoint"],
                "description": meta["description"],
                "objective": meta["objective"],
                "free_hint": meta["hints"][0],
                "guide": HARDENING_GUIDE[cid],
            }
        )
    return jsonify({"challenges": items, "final_boss": False, "mode": "hardened"})


@app.post("/api/game/register")
def register_team():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)
    try:
        name = clean_text(data.get("teamName") or data.get("name"), field="teamName", maximum=40)
    except ValueError as exc:
        return api_error(str(exc), 400)
    members = data.get("members")
    if not isinstance(members, list) or not (1 <= len(members) <= 10):
        return api_error("members must contain between 1 and 10 names", 400)
    try:
        clean_members = [clean_text(member, field="member", maximum=60) for member in members]
    except ValueError as exc:
        return api_error(str(exc), 400)

    db = get_db()
    now = time.time()
    client_key = hashlib.sha256((request.remote_addr or "unknown").encode("utf-8")).hexdigest()
    db.execute("BEGIN IMMEDIATE")
    registration = db.execute(
        "SELECT * FROM registration_counters WHERE client_key = ?", (client_key,)
    ).fetchone()
    if not registration or now - float(registration["window_start"]) >= REGISTRATION_WINDOW_SECONDS:
        if registration:
            db.execute(
                "UPDATE registration_counters SET count = 1, window_start = ? WHERE client_key = ?",
                (now, client_key),
            )
        else:
            db.execute(
                "INSERT INTO registration_counters (client_key, count, window_start) VALUES (?, 1, ?)",
                (client_key, now),
            )
        db.commit()
    elif int(registration["count"]) >= REGISTRATION_LIMIT:
        retry_after = max(
            1,
            int(
                REGISTRATION_WINDOW_SECONDS
                - (now - float(registration["window_start"]))
            ),
        )
        db.commit()
        response = jsonify({"error": "Registration rate limit exceeded"})
        response.headers["Retry-After"] = str(retry_after)
        return response, 429
    else:
        db.execute(
            "UPDATE registration_counters SET count = count + 1 WHERE client_key = ?",
            (client_key,),
        )
        db.commit()

    # In hardened mode registration is optional and exists only to mint an
    # isolated token for hands-on negative tests. A completed legacy game
    # session must not prevent access to that testing identity.
    session = read_session(db)
    assigned = 1

    existing = db.execute("SELECT * FROM teams WHERE name = ?", (name,)).fetchone()
    if existing:
        authenticated, auth_error = authenticate_team()
        if auth_error:
            return auth_error
        if authenticated["id"] != existing["id"]:
            return api_error("The access token does not own this team", 403)
        db.execute(
            "UPDATE teams SET members = ?, assigned_challenge = ? WHERE id = ?",
            (json.dumps(clean_members), existing["assigned_challenge"] or assigned, existing["id"]),
        )
        db.commit()
        team = db.execute("SELECT * FROM teams WHERE id = ?", (existing["id"],)).fetchone()
        return jsonify(
            {
                "team": public_team(team),
                "accessToken": issue_team_token(team),
                "tokenType": "Bearer",
                "expiresIn": TOKEN_TTL_SECONDS,
                "profileId": int(team["id"]),
                "assignedChallenge": team["assigned_challenge"] or assigned,
                "resumed": True,
                "session": read_session(db),
                "message": f"Welcome back, Team {name}!",
            }
        )

    cur = db.execute(
        """
        INSERT INTO teams (name, points, hints_used, created_at, members, assigned_challenge, auth_nonce)
        VALUES (?, 0, 0, ?, ?, ?, ?)
        """,
        (name, utc_now(), json.dumps(clean_members), assigned, secrets.token_urlsafe(32)),
    )
    team_id = cur.lastrowid
    db.execute(
        """
        INSERT INTO team_accounts (team_id, name, email, role, balance)
        VALUES (?, ?, ?, 'user', 1000)
        """,
        (team_id, name, f"team-{team_id}@heist.local"),
    )
    for cid in CHALLENGES:
        db.execute(
            "INSERT INTO challenge_progress (team_id, challenge_id) VALUES (?, ?)",
            (team_id, cid),
        )
    db.commit()
    team = db.execute("SELECT * FROM teams WHERE id = ?", (team_id,)).fetchone()
    return jsonify(
        {
            "team": public_team(team),
            "accessToken": issue_team_token(team),
            "tokenType": "Bearer",
            "expiresIn": TOKEN_TTL_SECONDS,
            "profileId": int(team["id"]),
            "assignedChallenge": assigned,
            "resumed": False,
            "session": read_session(db),
            "message": f"Team {name} registered for challenge {assigned}!",
        }
    )


@app.get("/api/game/session")
def get_session():
    db = get_db()
    return jsonify(read_session(db))


@app.post("/api/game/claim")
@require_team
def claim_challenge():
    """Assign the next open path challenge to a team (fixes null assignments)."""
    db = get_db()
    session, err = require_session_active(db)
    if err:
        return err

    team = g.current_team

    assigned = team["assigned_challenge"]
    shared = session["challenges"].get(int(assigned), {}) if assigned else {}
    if assigned and not shared.get("solved"):
        return jsonify(
            {
                "assignedChallenge": int(assigned),
                "session": session,
                "team": public_team(team),
            }
        )

    nxt = session["nextChallenge"]
    if nxt is None:
        return jsonify({"error": "No open challenge left to claim"}), 400

    db.execute(
        "UPDATE teams SET assigned_challenge = ? WHERE id = ?",
        (nxt, team["id"]),
    )
    db.commit()
    team = db.execute("SELECT * FROM teams WHERE id = ?", (team["id"],)).fetchone()
    return jsonify(
        {
            "assignedChallenge": nxt,
            "session": read_session(db),
            "team": public_team(team),
            "message": f"Assigned challenge {nxt}",
        }
    )


@app.post("/api/game/session/resume")
@require_team
def resume_session():
    db = get_db()
    session = read_session(db)
    if session["ended"] or session["remainingSeconds"] <= 0:
        persist_remaining(db, 0, False, True)
        return jsonify({"error": "Session time is over", "session": read_session(db)}), 403
    assigned = g.current_team["assigned_challenge"]
    if assigned is None or int(assigned) != session["nextChallenge"]:
        return api_error("Only the team assigned to the next challenge may resume the session", 403)
    persist_remaining(db, session["remainingSeconds"], True, False)
    return jsonify(read_session(db))


@app.post("/api/game/session/pause")
@require_team
def pause_session():
    db = get_db()
    session = read_session(db)
    if session["ended"]:
        return jsonify(session)
    assigned = g.current_team["assigned_challenge"]
    if assigned is None or int(assigned) != session["nextChallenge"]:
        return api_error("Only the assigned team may pause the session", 403)
    persist_remaining(db, session["remainingSeconds"], False, False)
    return jsonify(read_session(db))


@app.get("/api/game/state/<team_name>")
@require_team
def game_state(team_name: str):
    db = get_db()
    team = g.current_team
    if not hmac.compare_digest(team_name, team["name"]):
        return api_error("Object access denied", 403)
    rows = db.execute(
        "SELECT * FROM challenge_progress WHERE team_id = ? ORDER BY challenge_id",
        (team["id"],),
    ).fetchall()
    challenges = {}
    for row in rows:
        challenges[row["challenge_id"]] = {
            "solved": bool(row["solved"]),
            "hintsUsed": row["hints_used"],
            "time": row["time_seconds"],
            "requests": row["requests"],
            "pointsEarned": row["points_earned"],
            "solvedAt": row["solved_at"],
        }
    members = json.loads(team["members"] or "[]")
    return jsonify(
        {
            "team": public_team(team),
            "challenges": challenges,
            "session": read_session(db),
        }
    )


@app.post("/api/game/hint")
@require_team
def reveal_hint():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)
    try:
        challenge_id = int(data.get("challengeId") or 0)
        hint_index = int(data.get("hintIndex") if data.get("hintIndex") is not None else 1)
    except (TypeError, ValueError):
        return api_error("challengeId and hintIndex must be integers", 400)

    if challenge_id not in CHALLENGES:
        return jsonify({"error": "Invalid challenge"}), 400
    if hint_index not in (0, 1):
        return jsonify({"error": "Invalid hint index"}), 400

    db = get_db()
    _, err = require_session_active(db)
    if err:
        return err

    team = g.current_team
    if int(team["assigned_challenge"] or 0) != challenge_id:
        return api_error("This team is not assigned to that challenge", 403)

    progress = db.execute(
        "SELECT * FROM challenge_progress WHERE team_id = ? AND challenge_id = ?",
        (team["id"], challenge_id),
    ).fetchone()

    hint_text = CHALLENGES[challenge_id]["hints"][hint_index]
    deducted = 0

    if hint_index == 1 and progress and progress["hints_used"] < 1:
        db.execute(
            "UPDATE challenge_progress SET hints_used = hints_used + 1 WHERE id = ?",
            (progress["id"],),
        )
        db.execute(
            "UPDATE teams SET hints_used = hints_used + 1 WHERE id = ?",
            (team["id"],),
        )
        deducted = 5
        db.commit()

    return jsonify(
        {
            "hint": hint_text,
            "hintIndex": hint_index,
            "pointsDeducted": deducted,
            "hint_used": hint_index == 1,
        }
    )


@app.post("/api/game/submit-flag")
@require_team
def submit_flag():
    return api_error("Flag submission was retired in the hardened edition", 410)


@app.get("/api/game/leaderboard")
def leaderboard():
    db = get_db()
    teams = db.execute(
        "SELECT * FROM teams ORDER BY points DESC, total_time_seconds ASC, created_at ASC"
    ).fetchall()
    solved_total = db.execute(
        "SELECT COUNT(*) FROM session_challenges WHERE solved = 1 AND challenge_id BETWEEN 1 AND 10"
    ).fetchone()[0]
    fastest = db.execute(
        """
        SELECT solved_by AS name, time_seconds AS best
        FROM session_challenges
        WHERE solved = 1 AND time_seconds IS NOT NULL AND challenge_id BETWEEN 1 AND 10
        ORDER BY time_seconds ASC
        LIMIT 1
        """
    ).fetchone()
    most_hints = db.execute(
        "SELECT name, hints_used FROM teams ORDER BY hints_used DESC LIMIT 1"
    ).fetchone()

    team_list = []
    for t in teams:
        team_list.append(
            {
                "name": t["name"],
                "points": int(t["points"]),
                "total_time_seconds": int(t["total_time_seconds"]),
            }
        )

    return jsonify(
        {
            "teams": team_list,
            "session": read_session(db),
            "stats": {
                "challengesSolved": solved_total,
                "challengesTotal": 10,
                "fastestSolve": (
                    {"team": fastest["name"], "seconds": fastest["best"]} if fastest else None
                ),
                "mostHints": (
                    {"team": most_hints["name"], "hints": most_hints["hints_used"]}
                    if most_hints and most_hints["hints_used"]
                    else None
                ),
            },
        }
    )


@app.post("/api/game/restart")
def restart_game():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)
    full = bool(data.get("fullReset"))
    db = get_db()
    if full:
        admin_error = authenticate_admin()
        if admin_error:
            return admin_error
        db.execute("DELETE FROM challenge_progress")
        db.execute("DELETE FROM teams")
        db.execute("DELETE FROM rate_counters")
        db.execute("DELETE FROM registration_counters")
        db.execute("DELETE FROM transfer_counters")
        db.execute("DELETE FROM transfers")
        db.execute("DELETE FROM webhook_deliveries")
        db.execute("DELETE FROM session_challenges")
        for cid in range(1, 12):
            db.execute(
                "INSERT INTO session_challenges (challenge_id, solved) VALUES (?, 0)",
                (cid,),
            )
        db.execute(
            "UPDATE game_session SET remaining_seconds = ?, running = 0, ended = 0, updated_at = ? WHERE id = 1",
            (SESSION_DURATION, time.time()),
        )
        for user in DEMO_USERS:
            db.execute(
                "UPDATE users_demo SET name = ?, email = ?, role = ?, balance = ?, extra = ? WHERE id = ?",
                (
                    user["name"],
                    user["email"],
                    user["role"],
                    user["balance"],
                    json.dumps(
                        {
                            key: value
                            for key, value in user.items()
                            if key not in ("id", "name", "email", "role", "balance")
                        }
                    ),
                    user["id"],
                ),
            )
        db.commit()
        return jsonify({"message": "Full game reset complete.", "session": read_session(db)})

    team, auth_error = authenticate_team()
    if auth_error:
        return auth_error
    name = team["name"]
    supplied_name = data.get("teamName")
    if supplied_name is not None and supplied_name != name:
        return api_error("Object access denied", 403)
    counter_key = f"team:{team['id']}"
    db.execute("DELETE FROM challenge_progress WHERE team_id = ?", (team["id"],))
    db.execute("DELETE FROM teams WHERE id = ?", (team["id"],))
    db.execute("DELETE FROM rate_counters WHERE team_key = ?", (counter_key,))
    db.execute("DELETE FROM transfer_counters WHERE team_key = ?", (counter_key,))
    db.execute("DELETE FROM transfers WHERE team_key = ?", (counter_key,))
    db.commit()
    return jsonify({"message": f"Team {name} reset."})


# ---------------------------------------------------------------------------
# Challenge 1 — BOLA
# ---------------------------------------------------------------------------


@app.get("/api/user/<int:user_id>")
@require_team
def get_user(user_id: int):
    track_request(1)
    if user_id != int(g.auth_claims["user_id"]):
        return api_error("Object access denied", 403)
    db = get_db()
    row = db.execute("SELECT * FROM team_accounts WHERE team_id = ?", (user_id,)).fetchone()
    if not row:
        return api_error("User not found", 404)
    user = {
        "id": row["team_id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "balance": row["balance"],
    }
    return ok("Profile loaded.", user=user)


# ---------------------------------------------------------------------------
# Challenge 2 — Broken Authentication
# ---------------------------------------------------------------------------


@app.get("/api/admin")
@require_admin
def admin_panel():
    track_request(2)
    return ok("Administrator authentication verified.", role="admin")


# ---------------------------------------------------------------------------
# Challenge 3 — Mass Assignment
# ---------------------------------------------------------------------------


@app.put("/api/user/update")
@require_team
def update_user():
    track_request(3)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)
    allowed = {"name", "email"}
    forbidden = sorted(set(data) - allowed)
    if forbidden:
        return api_error("Immutable or unknown properties are not accepted", 400, fields=forbidden)
    if not data:
        return api_error("At least one editable property is required", 400)
    try:
        name = clean_text(data.get("name", "Alice"), field="name", maximum=80)
        email = clean_text(data.get("email", "alice@heist.local"), field="email", maximum=254)
    except ValueError as exc:
        return api_error(str(exc), 400)
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return api_error("email is invalid", 400)
    user_id = int(g.auth_claims["user_id"])
    db = get_db()
    db.execute("UPDATE team_accounts SET name = ?, email = ? WHERE team_id = ?", (name, email, user_id))
    db.commit()
    row = db.execute(
        "SELECT team_id AS id, name, email, role, balance FROM team_accounts WHERE team_id = ?",
        (user_id,),
    ).fetchone()
    return ok("Profile updated.", user=dict(row))


# ---------------------------------------------------------------------------
# Challenge 4 — Resource Consumption / Rate Limit
# ---------------------------------------------------------------------------


@app.get("/api/rate-limited")
@require_team
def rate_limited():
    track_request(4)
    key = team_key_from_request()
    db = get_db()
    now = time.time()
    db.execute("BEGIN IMMEDIATE")
    row = db.execute("SELECT * FROM rate_counters WHERE team_key = ?", (key,)).fetchone()
    if not row or now - float(row["window_start"]) >= RATE_WINDOW_SECONDS:
        if row:
            db.execute(
                "UPDATE rate_counters SET count = 1, window_start = ? WHERE team_key = ?",
                (now, key),
            )
        else:
            db.execute(
                "INSERT INTO rate_counters (team_key, count, window_start) VALUES (?, 1, ?)",
                (key, now),
            )
        db.commit()
        count = 1
    else:
        if int(row["count"]) >= RATE_LIMIT:
            retry_after = max(1, int(RATE_WINDOW_SECONDS - (now - float(row["window_start"]))))
            db.commit()
            response = jsonify({"error": "Rate limit exceeded"})
            response.headers["Retry-After"] = str(retry_after)
            return response, 429
        count = int(row["count"]) + 1
        db.execute("UPDATE rate_counters SET count = ? WHERE team_key = ?", (count, key))
        db.commit()
    return ok("Request accepted.", request_count=count, remaining=max(0, RATE_LIMIT - count))


# ---------------------------------------------------------------------------
# Challenge 5 — Broken Function Level Authorization
# ---------------------------------------------------------------------------


@app.delete("/api/admin/users")
@require_admin
def delete_users():
    track_request(5)
    return ok(
        "Administrator authorization verified; no users were selected for deletion.",
        deleted=[],
    )


# ---------------------------------------------------------------------------
# Challenge 6 — Business Flow Abuse
# ---------------------------------------------------------------------------


@app.post("/api/transfer")
@require_team
def transfer():
    track_request(6)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)
    amount = data.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, int):
        return api_error("amount must be an integer", 400)
    if amount < 1 or amount > TRANSFER_MAX_AMOUNT:
        return api_error(f"amount must be between 1 and {TRANSFER_MAX_AMOUNT}", 400)
    recipient_ref = data.get("toUserId", data.get("to"))
    if recipient_ref is None:
        return api_error("toUserId or to is required", 400)
    idempotency_key = request.headers.get("Idempotency-Key", "")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", idempotency_key):
        return api_error("A valid Idempotency-Key header is required", 400)

    key = team_key_from_request()
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    existing = db.execute(
        "SELECT * FROM transfers WHERE team_key = ? AND idempotency_key = ?",
        (key, idempotency_key),
    ).fetchone()
    if existing:
        if int(existing["amount"]) != amount:
            db.rollback()
            return api_error("Idempotency key was already used for a different request", 409)
        db.commit()
        return ok(
            "Idempotent replay; the transfer was not repeated.",
            idempotent_replay=True,
            transfer={"id": existing["id"], "amount": existing["amount"]},
        )

    sender_id = int(g.auth_claims["user_id"])
    sender = db.execute("SELECT * FROM team_accounts WHERE team_id = ?", (sender_id,)).fetchone()
    if isinstance(recipient_ref, int) and not isinstance(recipient_ref, bool):
        recipient = db.execute("SELECT * FROM users_demo WHERE id = ?", (recipient_ref,)).fetchone()
    elif isinstance(recipient_ref, str) and recipient_ref.strip():
        recipient = db.execute(
            "SELECT * FROM users_demo WHERE lower(name) = lower(?)", (recipient_ref.strip(),)
        ).fetchone()
    else:
        recipient = None
    if not sender or not recipient:
        db.rollback()
        return api_error("Sender or recipient not found", 404)
    if int(sender["balance"]) < amount:
        db.rollback()
        return api_error("Insufficient balance", 409)

    now = time.time()
    counter = db.execute(
        "SELECT * FROM transfer_counters WHERE team_key = ?", (key,)
    ).fetchone()
    if not counter or now - float(counter["window_start"]) >= TRANSFER_WINDOW_SECONDS:
        count = 0
        total_amount = 0
        if counter:
            db.execute(
                "UPDATE transfer_counters SET count = 0, total_amount = 0, window_start = ? WHERE team_key = ?",
                (now, key),
            )
        else:
            db.execute(
                "INSERT INTO transfer_counters (team_key, count, window_start, total_amount) VALUES (?, 0, ?, 0)",
                (key, now),
            )
    else:
        count = int(counter["count"])
        total_amount = int(counter["total_amount"])
    if count >= TRANSFER_LIMIT_PER_WINDOW or total_amount + amount > TRANSFER_MAX_WINDOW_AMOUNT:
        db.rollback()
        return api_error("Transfer velocity limit exceeded", 429)

    db.execute(
        "UPDATE team_accounts SET balance = balance - ? WHERE team_id = ?", (amount, sender_id)
    )
    db.execute(
        "UPDATE users_demo SET balance = balance + ? WHERE id = ?", (amount, recipient["id"])
    )
    cursor = db.execute(
        """
        INSERT INTO transfers
            (team_key, idempotency_key, from_user_id, to_user_id, amount, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (key, idempotency_key, sender_id, recipient["id"], amount, now),
    )
    db.execute(
        "UPDATE transfer_counters SET count = count + 1, total_amount = total_amount + ? WHERE team_key = ?",
        (amount, key),
    )
    db.commit()
    return ok(
        "Transfer completed.",
        idempotent_replay=False,
        transfer={
            "id": cursor.lastrowid,
            "fromUserId": sender_id,
            "toUserId": recipient["id"],
            "amount": amount,
        },
        balance=int(sender["balance"]) - amount,
    )


# ---------------------------------------------------------------------------
# Challenge 7 — SSRF
# ---------------------------------------------------------------------------


@app.get("/api/internal/flag")
def internal_flag():
    return api_error("Not found", 404)


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_host_is_allowed(host: str) -> bool:
    return host in FETCH_ALLOWLIST


def host_resolves_publicly(host: str, port: int) -> bool:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    if not addresses:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


@app.post("/api/fetch-url")
@require_team
def fetch_url():
    track_request(7)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        return api_error("A JSON body containing url is required", 400)
    url = data["url"].strip()
    if len(url) > 2048:
        return api_error("url is too long", 400)
    try:
        parsed = urlparse(url)
        port = parsed.port or 443
    except ValueError:
        return api_error("url is invalid", 400)
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port != 443
        or parsed.fragment
    ):
        return api_error("Only credential-free HTTPS URLs on port 443 are accepted", 400)
    if not fetch_host_is_allowed(host):
        return api_error("Destination host is not allowlisted", 403)
    if not host_resolves_publicly(host, port):
        return api_error("Destination must resolve only to public IP addresses", 403)

    try:
        opener = build_opener(NoRedirectHandler())
        outbound = Request(url, headers={"User-Agent": "API-Heist-Academy/2.0"})
        with opener.open(outbound, timeout=3) as response:
            content_type = response.headers.get_content_type()
            if not (content_type.startswith("text/") or content_type == "application/json"):
                return api_error("Upstream content type is not accepted", 415)
            body = response.read(FETCH_MAX_BYTES + 1)
        if len(body) > FETCH_MAX_BYTES:
            return api_error("Upstream response is too large", 502)
        snippet = body.decode("utf-8", errors="replace")[:500]
        return ok("Allowlisted URL fetched.", fetched={"url": url, "snippet": snippet})
    except Exception:
        return api_error("Upstream fetch failed", 502)


# ---------------------------------------------------------------------------
# Challenge 8 — Misconfiguration
# ---------------------------------------------------------------------------


@app.get("/api/debug")
def debug_endpoint():
    return api_error("Not found", 404)


# ---------------------------------------------------------------------------
# Challenge 9 — Improper Inventory / deprecated API
# ---------------------------------------------------------------------------


@app.get("/api/v2/users")
@require_team
def users_v2():
    user_id = int(g.auth_claims["user_id"])
    row = get_db().execute(
        "SELECT team_id AS id, name FROM team_accounts WHERE team_id = ?", (user_id,)
    ).fetchone()
    return jsonify(
        {
            "version": "v2",
            "users": [dict(row)] if row else [],
        }
    )


@app.get("/api/v1/users")
def users_v1():
    response = jsonify({"error": "API v1 has been retired; use /api/v2/users"})
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Sat, 22 Aug 2026 00:00:00 GMT"
    response.headers["Link"] = '</api/v2/users>; rel="successor-version"'
    return response, 410


# ---------------------------------------------------------------------------
# Challenge 10 — Unsafe Consumption of APIs / Webhook
# ---------------------------------------------------------------------------


@app.post("/api/webhook")
def webhook():
    if not WEBHOOK_SECRET:
        return api_error("Webhook processing is disabled until DVAPI_WEBHOOK_SECRET is configured", 503)
    raw_body = request.get_data(cache=True)
    timestamp_header = request.headers.get("X-Webhook-Timestamp", "")
    signature = request.headers.get("X-Webhook-Signature", "")
    try:
        timestamp = int(timestamp_header)
    except ValueError:
        return api_error("Webhook authentication failed", 401)
    now = int(time.time())
    if timestamp > now + 30 or now - timestamp > WEBHOOK_MAX_AGE_SECONDS:
        return api_error("Webhook authentication failed", 401)
    if not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        return api_error("Webhook authentication failed", 401)
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        timestamp_header.encode("ascii") + b"." + raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return api_error("Webhook authentication failed", 401)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("A JSON object is required", 400)
    event = data.get("event")
    if event not in {"ping", "transfer.completed", "user.updated"}:
        return api_error("Unsupported webhook event", 400)
    if "payload" not in data:
        return api_error("payload is required", 400)
    payload = data["payload"]
    try:
        encoded_payload = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return api_error("payload is invalid", 400)
    if len(encoded_payload.encode("utf-8")) > 4096:
        return api_error("payload is too large", 400)

    db = get_db()
    db.execute(
        "DELETE FROM webhook_deliveries WHERE received_at < ?",
        (time.time() - (WEBHOOK_MAX_AGE_SECONDS * 2),),
    )
    if db.execute(
        "SELECT 1 FROM webhook_deliveries WHERE signature = ?", (signature,)
    ).fetchone():
        db.commit()
        return api_error("Webhook replay rejected", 409)
    db.execute(
        "INSERT INTO webhook_deliveries (signature, received_at) VALUES (?, ?)",
        (signature, time.time()),
    )
    db.commit()
    return jsonify({"accepted": True, "event": event}), 202


# ---------------------------------------------------------------------------
# Final Boss
# ---------------------------------------------------------------------------


@app.post("/api/ultimate-challenge")
def ultimate_challenge():
    return api_error("The flag aggregation endpoint was retired in the hardened edition", 410)


# ---------------------------------------------------------------------------
# Frontend + health
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "API Heist Academy"})


@app.get("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.get("/<path:path>")
def static_proxy(path: str):
    if path.startswith("api/"):
        return api_error("Not found", 404)
    static_root = STATIC_DIR.resolve()
    target = (STATIC_DIR / path).resolve()
    if target.is_relative_to(static_root) and target.is_file():
        return send_from_directory(STATIC_DIR, path)
    return send_from_directory(STATIC_DIR, "index.html")


init_db()


if __name__ == "__main__":
    print("=" * 60)
    print("API Heist Academy — HARDENED EDITION")
    print(f"Serving on http://{HOST}:{PORT}")
    if not ADMIN_TOKEN:
        print("Admin operations disabled: configure DVAPI_ADMIN_TOKEN to enable them.")
    if not WEBHOOK_SECRET:
        print("Webhook processing disabled: configure DVAPI_WEBHOOK_SECRET to enable it.")
    print("=" * 60)
    app.run(host=HOST, port=PORT, debug=False)
