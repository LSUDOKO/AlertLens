"""FastAPI app. It has no login, so it binds to localhost by default."""
from __future__ import annotations

import os
import threading
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from alertlens import __version__
from alertlens.api import errors, routes_analysis, routes_incidents, routes_ops, routes_v2
from alertlens.config import get_settings

MAX_BODY_BYTES = 10_000_000
PUBLIC_MAX_BODY_BYTES = 64_000
PUBLIC_RATE_PER_MINUTE = 60
# A public demo is shared by everyone, so nothing that changes shared state or picks a model is allowed.
PUBLIC_BLOCKED = ("/feedback", "/retrain", "/actions/", "/stream/replay", "/analyze/batch")


def _init_sentry() -> None:
    """Error reporting is opt-in: nothing is sent unless SENTRY_DSN is set."""
    if dsn := os.environ.get("SENTRY_DSN"):
        import sentry_sdk

        sentry_sdk.init(dsn=dsn, traces_sample_rate=0.0, send_default_pii=False, release=f"alertlens@{__version__}")


_init_sentry()

app = FastAPI(title="AlertLens", version=__version__,
              description="Injection-resistant, evidence-grounded security alert explainer. Synthetic data only.")
errors.install(app)
app.include_router(routes_analysis.router)
app.include_router(routes_incidents.router)
app.include_router(routes_ops.router)
app.include_router(routes_v2.router)
_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["GET", "POST"], allow_headers=["content-type"])
_hits: dict[str, list[float]] = {}
_hits_lock = threading.Lock()


def _client(request: Request) -> str:
    # Behind one proxy (Render), the last entry is the address the proxy saw; earlier ones are client-supplied and forgeable.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[-1].strip() or (request.client.host if request.client else "unknown")


def _rate_limited(key: str) -> bool:
    """A sliding one-minute window per client. In memory, so it resets on restart."""
    now = time.monotonic()
    with _hits_lock:
        recent = [t for t in _hits.get(key, []) if now - t < 60]
        recent.append(now)
        _hits[key] = recent
        if len(_hits) > 10_000:
            _hits.clear()
        return len(recent) > PUBLIC_RATE_PER_MINUTE


@app.middleware("http")
async def public_demo_guard(request: Request, call_next):
    if get_settings().public_demo and request.method != "OPTIONS":
        path = request.url.path
        if request.method == "POST" and any(path == p or path.startswith(p) for p in PUBLIC_BLOCKED):
            return JSONResponse({"error": "public_demo", "detail": "Turned off on the public demo. Run AlertLens locally."},
                                status_code=403)
        size = request.headers.get("content-length")
        if size and size.isdigit() and int(size) > PUBLIC_MAX_BODY_BYTES:
            return JSONResponse({"error": "too_large", "detail": f"Body over {PUBLIC_MAX_BODY_BYTES} bytes"}, status_code=413)
        if _rate_limited(_client(request)):
            return JSONResponse({"error": "rate_limited", "detail": "Too many requests. Try again in a minute."}, status_code=429)
    return await call_next(request)


@app.middleware("http")
async def limit_body(request: Request, call_next):
    size = request.headers.get("content-length")
    if size and size.isdigit() and int(size) > MAX_BODY_BYTES:
        return JSONResponse({"error": "too_large", "detail": f"Body over {MAX_BODY_BYTES} bytes"}, status_code=413)
    return await call_next(request)


@app.get("/health")
def health():
    s = get_settings()
    return {"status": "ok", "provider": s.llm_provider, "model": s.llm_model or "template", "version": __version__,
            "public_demo": s.public_demo}
