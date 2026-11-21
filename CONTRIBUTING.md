# Contributing to Admit

Two people, one weekend, one main branch that always works. Keep it boring.

## Setup

Install `uv` (see https://docs.astral.sh/uv/getting-started/installation/), then:

**Windows (PowerShell)**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
uv sync
Copy-Item .env.example .env
```

**macOS / Linux**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync
cp .env.example .env
```

Fill in `GOOGLE_API_KEY` / `GEMINI_API_KEY` in `.env` (https://aistudio.google.com/apikey).
Tests and lint must not need any API key.

## Tests and lint

```bash
uv run pytest
uv run pytest -q tests/test_smoke.py   # fast sanity check
uv run ruff check .
uv run ruff check --fix .              # autofix imports/formatting nits
```

## Branch workflow

- Short-lived branches off `main`, one topic each: `<your-name>/<topic>`
  (e.g. `anees/audit-chain`).
- Small PRs into `main`. Prefer several small PRs over one big one.
- Rebase on `main` often: `git fetch && git rebase origin/main`. Resolve conflicts in your branch.
- `main` must always run the demo end to end: `uv run admit demo`.
- Never force-push `main`. Force-push your own topic branch only.

## Who works on what

The full plan, milestones and work items are in [docs/dev/plan.md](docs/dev/plan.md). Claim a
work item before starting so two people never edit the same module at once.

Shared contracts in `admit/types.py` change **only by agreement** — ping the other person in the PR
before touching it, and land contract changes first so the other side can rebase.

Touching files you don't own is fine when it unblocks you; say so in the PR.

## Commits

- Imperative mood, one line under ~72 chars: `Add hash chaining to audit log`.
- Body optional; explain the why, not the diff.
- No AI co-author trailers, no `Co-authored-by: <assistant>` lines.

## Secrets

- Never commit real secrets. `.env` is gitignored; only `.env.example` (empty values) is tracked.
- If a key leaks into a commit, rotate it — don't just delete the line.
