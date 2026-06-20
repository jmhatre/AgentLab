"""
cloud/src/agent_loop_secure.py
------------------------------
Step 2: Add path allowlist, traversal prevention, loop budget cap,
and structured audit logging.

Exposures fixed here: S1-02, S1-03, S1-04, S1-05
Still open:          S1-01 (prompt injection), S1-06 (identity), S1-07 (redaction)
"""

import json
import logging
import pathlib
import uuid
from datetime import datetime, timezone

import anthropic

# ---------------------------------------------------------------------------
# Sandbox — the ONLY directory the agent is allowed to read from.
# Change this to whatever directory makes sense for your use case.
# ---------------------------------------------------------------------------
SANDBOX = pathlib.Path("/tmp/agent_sandbox")

# ---------------------------------------------------------------------------
# Structured audit logger
# ---------------------------------------------------------------------------
# We use a dedicated logger (not the root logger) so it can be configured
# independently — sent to a file, a SIEM, or a cloud log sink in production.
#
# FORMAT: one JSON object per line (newline-delimited JSON / NDJSON).
# This is the most interoperable format for log aggregators.

_audit = logging.getLogger("agent.audit")
_audit.setLevel(logging.INFO)

if not _audit.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _audit.addHandler(_handler)


def _log(event: str, **fields) -> None:
    """Emit one structured audit log line."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    _audit.info(json.dumps(record))


# ---------------------------------------------------------------------------
# Tool definition — identical to Step 1; the schema itself hasn't changed.
# The security controls live in execute_tool(), not the schema.
# ---------------------------------------------------------------------------
TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read the contents of a file inside the agent sandbox "
            "and return them as a string."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file (must be inside the sandbox).",
                }
            },
            "required": ["path"],
        },
    }
]


# ---------------------------------------------------------------------------
# Path validation helper — the core of Layer 2 hardening
# ---------------------------------------------------------------------------

def _validate_path(raw_path: str) -> pathlib.Path:
    """Resolve and validate a path against the sandbox allowlist.

    Steps:
      1. Parse the raw string into a Path object.
      2. resolve() expands symlinks and collapses ../../ traversal sequences.
      3. Assert the resolved path starts with SANDBOX.
         If not, raise ValueError — the caller turns this into an error string.

    Args:
        raw_path: The path string supplied by the model.

    Returns:
        The resolved pathlib.Path, guaranteed to be inside SANDBOX.

    Raises:
        ValueError: If the path escapes the sandbox.
    """
    resolved = pathlib.Path(raw_path).resolve()

    # Path.is_relative_to() requires Python 3.9+.
    # For broader compatibility we use the string prefix check below.
    try:
        resolved.relative_to(SANDBOX)
    except ValueError:
        raise ValueError(
            f"Path '{resolved}' is outside the allowed sandbox '{SANDBOX}'. "
            "Only files inside the sandbox may be read."
        )

    return resolved


# ---------------------------------------------------------------------------
# Tool executor — now with validation and logging
# ---------------------------------------------------------------------------

def execute_tool(tool_name: str, tool_input: dict, run_id: str) -> str:
    """Run the requested tool, validate arguments, log the call, return result.

    Args:
        tool_name:  Name from the model's tool_use block.
        tool_input: Arguments the model supplied.
        run_id:     Unique identifier for this agent run (for log correlation).

    Returns:
        A string result or a descriptive error message.
    """

    if tool_name == "read_file":
        raw_path = tool_input.get("path", "")

        # --- FIX S1-02 + S1-03: path allowlist + traversal prevention -------
        try:
            safe_path = _validate_path(raw_path)
        except ValueError as exc:
            _log("tool_blocked", run_id=run_id, tool=tool_name,
                 raw_path=raw_path, reason=str(exc))
            return f"Error: {exc}"

        # --- FIX S1-04: audit log every tool call ----------------------------
        _log("tool_call", run_id=run_id, tool=tool_name, path=str(safe_path))

        try:
            contents = safe_path.read_text(encoding="utf-8")
            _log("tool_result", run_id=run_id, tool=tool_name,
                 path=str(safe_path), result_bytes=len(contents.encode()))

            # STILL OPEN — S1-01 (prompt injection) and S1-07 (redaction):
            #   Contents are still returned verbatim. Fixed in a later step.
            return contents

        except FileNotFoundError:
            _log("tool_error", run_id=run_id, tool=tool_name,
                 path=str(safe_path), error="file_not_found")
            return f"Error: file not found: {safe_path}"
        except PermissionError:
            _log("tool_error", run_id=run_id, tool=tool_name,
                 path=str(safe_path), error="permission_denied")
            return f"Error: permission denied: {safe_path}"
        except Exception as exc:
            _log("tool_error", run_id=run_id, tool=tool_name,
                 path=str(safe_path), error=str(exc))
            return f"Error reading file: {exc}"

    _log("tool_unknown", run_id=run_id, tool=tool_name)
    return f"Error: unknown tool '{tool_name}'"


# ---------------------------------------------------------------------------
# The tool-use loop — now with a turn budget
# ---------------------------------------------------------------------------

class BudgetExceededError(Exception):
    """Raised when the agent exceeds its turn limit."""


def run_agent(
    user_message: str,
    max_turns: int = 10,
    verbose: bool = True,
) -> str:
    """Run the tool-use loop with security controls.

    Args:
        user_message: The human's question or instruction.
        max_turns:    Maximum number of API round-trips allowed.
                      Raises BudgetExceededError if exceeded.
                      Default 10 — adjust based on your use case.
        verbose:      Print a trace of each turn to stdout.

    Returns:
        The model's final text response.

    Raises:
        BudgetExceededError: If the loop exceeds max_turns.
    """

    # Each run gets a unique ID so its log lines can be correlated.
    run_id = str(uuid.uuid4())[:8]

    _log("run_start", run_id=run_id, user_message=user_message[:200],
         max_turns=max_turns)

    # Ensure the sandbox directory exists before the agent tries to read from it.
    SANDBOX.mkdir(parents=True, exist_ok=True)

    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": user_message}]

    for turn in range(1, max_turns + 1):
        if verbose:
            print(f"\n{'='*60}")
            print(f"  TURN {turn}/{max_turns} — run_id={run_id}")
            print(f"{'='*60}")

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            tools=TOOLS,
            messages=messages,
        )

        if verbose:
            print(f"  stop_reason : {response.stop_reason}")
            print(f"  content blocks: {[b.type for b in response.content]}")

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    _log("run_end", run_id=run_id, turns_used=turn,
                         answer_chars=len(block.text))
                    if verbose:
                        print(f"\n  FINAL ANSWER:\n  {block.text}")
                    return block.text
            return ""

        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue

                if verbose:
                    print(f"\n  TOOL CALL  : {block.name}")
                    print(f"  tool_use_id: {block.id}")
                    print(f"  arguments  : {block.input}")

                result_content = execute_tool(block.name, block.input, run_id)

                if verbose:
                    preview = result_content[:200].replace("\n", "\\n")
                    print(f"  tool result: {preview}{'...' if len(result_content) > 200 else ''}")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_content,
                })

            messages.append({"role": "user", "content": tool_results})

        else:
            raise RuntimeError(f"Unexpected stop_reason: {response.stop_reason}")

    # --- FIX S1-05: budget cap -----------------------------------------------
    _log("run_budget_exceeded", run_id=run_id, max_turns=max_turns)
    raise BudgetExceededError(
        f"Agent exceeded max_turns={max_turns}. "
        "Possible runaway loop — check the audit log."
    )


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    # Write a test file inside the sandbox.
    SANDBOX.mkdir(parents=True, exist_ok=True)
    test_file = SANDBOX / "hello.txt"
    test_file.write_text("Hello from the sandbox!\nThe answer is 42.\n")

    print(f"Sandbox: {SANDBOX}")
    print(f"Test file: {test_file}\n")

    # --- Demo 1: legitimate read ---
    print("=== Demo 1: legitimate read ===")
    answer = run_agent(f"Read the file at {test_file} and tell me what it says.")
    print(f"\nAnswer: {answer}\n")

    # --- Demo 2: path traversal attempt (should be blocked) ---
    print("=== Demo 2: path traversal blocked ===")
    try:
        run_agent("Read the file at /etc/passwd and tell me the first line.",
                  verbose=False)
    except Exception as exc:
        print(f"Caught: {exc}")

    # Cleanup
    test_file.unlink()
    print("\nDone.")
