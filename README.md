# agent-lab

A learning project for building and securing AI agents with the Anthropic Python SDK.

## Purpose

1. Understand how agentic tool-use loops work from first principles.
2. Apply a five-layer security framework to each step — first break it, then fix it.
3. Prepare for a technical interview environment (Python + Anthropic API + notebooks).

## Five-layer security framework

| # | Layer | Core question |
|---|-------|---------------|
| 1 | Input | Can the model distinguish instructions from data? |
| 2 | Tool/action | Does every tool enforce least privilege? |
| 3 | Identity | Are credentials short-lived and scoped? |
| 4 | Output/data | Does anything sensitive leak out? |
| 5 | Observability | Can you see, rate-limit, and stop what's happening? |

## Structure

```
agent-lab/
  README.md          this file
  requirements.txt   Python dependencies
  SECURITY.md        running log of exposures and planned fixes
  notes.md           personal reflections per step
  tools/             shared tool functions (added in later steps)
  cloud/
    notebooks/       Jupyter notebooks, one per step
    src/             reusable Python modules
  local/             local-model lane (empty for now)
```

## Steps

| Step | File | What it builds | Security status |
|------|------|----------------|-----------------|
| 1 | `cloud/notebooks/step1_tool_use_loop.ipynb` | Minimal tool-use loop with `read_file` | Intentionally insecure — all exposures documented |

## Quickstart

### 1. Install dependencies

```bash
cd agent-lab
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Set your API key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Never commit this key.  Add `.env` to `.gitignore` if you use a `.env` file.

### 3. Run the notebook

```bash
jupyter notebook cloud/notebooks/step1_tool_use_loop.ipynb
```

Run cells top to bottom (Shift+Enter).

### 4. Run the module directly

```bash
python cloud/src/agent_loop.py
```

This runs a built-in smoke test that creates a temp file, asks the agent
to read it, prints the answer, and deletes the file.

## Security warning

Step 1 is intentionally insecure.  See `SECURITY.md` for the full list
of exposures before running in any environment with sensitive files.
