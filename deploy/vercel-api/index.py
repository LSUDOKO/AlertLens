"""Vercel entrypoint: the same FastAPI app, locked by PUBLIC_DEMO=true in the project's environment."""
from alertlens.api.main import app  # noqa: F401
