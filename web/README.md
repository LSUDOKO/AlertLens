# AlertLens website

The public site for AlertLens: a static Next.js export served by Cloudflare Workers Static Assets. Every live panel calls the AlertLens FastAPI backend; the site has no server code of its own.

## Run it locally
Needs Node 24 and the API running from the repository root.

```bash
# terminal 1, repository root
ALLOWED_ORIGINS=http://localhost:8787 PYTHONPATH=. .venv/bin/uvicorn alertlens.api.main:app --port 8000

# terminal 2, web/
npm install
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000 npm run preview   # builds, then serves on http://localhost:8787
```

## Test it
With both servers running: `npx playwright install chromium` once, then `npm run test:e2e`. The six tests drive the analyzer, red team, adaptive attacker, incident graph and results against the real API, check the results match the committed benchmark files, fail on any console error, and check a phone screen does not scroll sideways.

## Deploy
```bash
NEXT_PUBLIC_API_URL=https://alertlens-api.onrender.com npm run deploy
```
`wrangler.jsonc` serves `out/`; `public/_headers` sets the security headers, including a content security policy that allows calls only to the API. If the API moves, update `connect-src` there and `ALLOWED_ORIGINS` on the API.

## Other scripts
- `npm run api:types` regenerates `src/lib/api-schema.ts` from the API's OpenAPI schema.
- `npm run record:hero` re-records the hero video from the running site.

## Credits
Archive photographs are public domain from Wikimedia Commons (`public/media/credits.json`), printed in red here. The paper-tear design is adapted from our Pharmakon project.
