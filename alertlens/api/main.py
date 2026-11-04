"""FastAPI app. It has no login, so it binds to localhost by default."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from alertlens import __version__
from alertlens.api import errors, routes_analysis, routes_incidents, routes_ops
from alertlens.config import get_settings

MAX_BODY_BYTES = 10_000_000

app = FastAPI(title="AlertLens", version=__version__,
              description="Injection-resistant, evidence-grounded security alert explainer. Synthetic data only.")
errors.install(app)
app.include_router(routes_analysis.router)
app.include_router(routes_incidents.router)
app.include_router(routes_ops.router)


@app.middleware("http")
async def limit_body(request: Request, call_next):
    size = request.headers.get("content-length")
    if size and size.isdigit() and int(size) > MAX_BODY_BYTES:
        return JSONResponse({"error": "too_large", "detail": f"Body over {MAX_BODY_BYTES} bytes"}, status_code=413)
    return await call_next(request)


@app.get("/health")
def health():
    s = get_settings()
    return {"status": "ok", "provider": s.llm_provider, "model": s.llm_model or "template", "version": __version__}
