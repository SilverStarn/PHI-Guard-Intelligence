# GitHub Launch Plan

This project is ready to present as a portfolio/product prototype once it is pushed to GitHub.

## Recommended Repository Setup

Repository name:

```text
PHI-Guard-Intelligence
```

Repository description:

```text
HIPAA-oriented healthcare data risk intelligence platform for PHI discovery, lineage, access exposure, de-identification readiness, and remediation evidence.
```

Suggested topics:

```text
healthcare
hipaa
privacy-engineering
data-governance
security
fastapi
react
typescript
python
phi
de-identification
risk-analysis
```

## GitHub First Impression

The README now opens with:

- Clear product pitch.
- Rendered console visual.
- Buyer/evaluator links.
- Technical quick start.
- Safety limitations.
- Documentation index.

Recommended pinned links:

- `docs/sales-one-pager.md`
- `presentations/phi-guard-intelligence-buyer-deck.md`
- `docs/technical-brief.md`
- `docs/real-client-readiness.md`
- `docs/no-raw-phi-storage.md`

## Push Checklist

Before pushing:

```powershell
npm test
python -m ruff check . --exclude node_modules --exclude apps/web/dist --exclude .pytest_cache --exclude .ruff_cache
npm --workspace @phi-guard-intelligence/web run build
```

Local runtime and generated folders are ignored:

```text
node_modules/
dist/
__pycache__/
.pytest_cache/
.ruff_cache/
.phi_guard/
*.tsbuildinfo
```

## If Pushing With Git CLI

Use this once the target repo is confirmed:

```powershell
git init -b main
git add .
git commit -m "Launch PHI Guard Intelligence"
git remote add origin https://github.com/SilverStarn/REPO_NAME.git
git push -u origin main
```

If the target repository already uses `master`, replace `main` with `master`.

## Post-Push Improvements

- Add repository social preview image from `docs/assets/console-preview.svg`.
- Add a release tagged `v0.1.0-mvp`.
- Enable GitHub Pages or attach the standalone HTML presentation to the README.
- Add screenshots from a live local demo once the API and web app are running.
- Add CI badges after the first successful workflow run.
