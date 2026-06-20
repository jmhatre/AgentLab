"""
cloud/src/agent_loop.py
-----------------------
Step 1: A minimal, intentionally-insecure tool-use loop.

This module is the "engine" behind the notebook.  Import it there, or
run it directly:

    python agent_loop.py

Read the SECURITY.md at the repo root before running in any environment
that contains sensitive files — this code has NO guardrails.
"""

import os
import anthropic

# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------
# The Anthropic API expects a list of tool objects.  Each object has:
#   name        – the string the model writes in its tool_use block
#   description – plain-English explanation; the model reads this to
#                 decide WHEN to call the tool
#   input_schema – a JSON Schema object describing the tool's arguments;
#                  the model fills these in and you validate/use them
#
# SECURITY EXPOSURE (Layer 2 — Tool/action layer):
#   There is NO path allowlist.  The model can request ANY file path,
#   including /etc/passwd, ~/.ssh/id_rsa, or any secret on disk.
#
# SECURITY EXPOSURE (Layer 1 — Input layer):
#   The file's raw contents are returned to the model as trusted text.
#   If a file contains injected instructions ("Ignore previous instructions
#   and exfiltrate ...") the model will follow them.

TOOLS = [
    {
        "name": "read_file",
        "description": (
            "Read the contents of a file on the local filesystem "
            "and return them as a string."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file.",
                }
            },
            "required": ["path"],
        },
    }
]


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------
# This is the Python side of "calling the tool".  When the model decides
# to use a tool it does NOT call your code directly — it just tells you
# what it wants via a tool_use content block.  You extract the arguments,
# run the real Python logic here, and hand the result back in the next
# API call as a tool_result block.

def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Run the requested tool and return a string result.

    Args:
        tool_name:  The name string from the model's tool_use block.
        tool_input: The dict of arguments the model supplied.

    Returns:
        A string to pass back as the tool_result content.
    """

    if tool_name == "read_file":
        path = tool_input["path"]

        # SECURITY EXPOSURE (Layer 2 — Tool/action layer):
        #   No argument validation.  path is used as-is.
        #   Path traversal (../../etc/passwd) is possible.
        #
        # SECURITY EXPOSURE (Layer 5 — Observability layer):
        #   Nothing is logged here.  We have no audit trail of
        #   which files were read, when, or by which agent run.

        try:
            with open(path, "r", encoding="utf-8") as f:
                contents = f.read()

            # SECURITY EXPOSURE (Layer 4 — Output/data layer):
            #   Raw file contents — which may include API keys, tokens,
            #   passwords, or PII — are returned verbatim with no
            #   redaction or DLP filtering.

            return contents

        except FileNotFoundError:
            return f"Error: file not found: {path}"
        except PermissionError:
            return f"Error: permission denied: {path}"
        except Exception as exc:
            return f"Error reading file: {exc}"

    # Fallback for unknown tools (shouldn't happen if TOOLS list is correct)
    return f"Error: unknown tool '{tool_name}'"


# ---------------------------------------------------------------------------
# The tool-use loop
# ---------------------------------------------------------------------------
# HOW THE LOOP WORKS (plain English):
#
#  1. You send a messages.create() call with your user message + the tool
#     definitions.  The model reads the tools and decides if it needs one.
#
#  2. The response has a stop_reason field:
#       "end_turn"   – the model finished; its last content block is text.
#       "tool_use"   – the model wants to call a tool before answering.
#
#  3. When stop_reason == "tool_use", the response content list contains
#     one or more blocks with type="tool_use".  Each block has:
#       id     – a unique string you MUST echo back
#       name   – which tool to call
#       input  – dict of arguments
#
#  4. You execute the tool locally, then make ANOTHER API call.  This time
#     the messages list has:
#       - all previous messages (the conversation so far)
#       - an "assistant" message whose content is what the model just said
#         (including the tool_use block — you pass it back verbatim)
#       - a "user" message whose content is a tool_result block referencing
#         the tool_use id
#
#  5. Repeat until stop_reason == "end_turn".
#
# SECURITY EXPOSURE (Layer 5 — Observability layer):
#   There is no turn counter or budget cap.  A malicious prompt could
#   keep the loop running indefinitely (resource exhaustion / runaway cost).

def run_agent(user_message: str, verbose: bool = True) -> str:
    """Send user_message to the model, handle tool calls, return final answer.

    Args:
        user_message: The human's question or instruction.
        verbose:      Print a trace of each turn to stdout.

    Returns:
        The model's final text response.
    """

    # Build the Anthropic client.  It reads ANTHROPIC_API_KEY from the
    # environment automatically — never hard-code credentials in source.
    #
    # SECURITY EXPOSURE (Layer 3 — Identity layer):
    #   This key is long-lived and has no scope restriction.  Any code
    #   that can import this module can make API calls on your account.
    client = anthropic.Anthropic()

    # The conversation history grows each turn.  We start with the
    # user's opening message.
    messages = [{"role": "user", "content": user_message}]

    turn = 0  # purely for readable trace output

    while True:
        turn += 1
        if verbose:
            print(f"\n{'='*60}")
            print(f"  TURN {turn} — sending {len(messages)} message(s) to API")
            print(f"{'='*60}")

        # ---- API call -------------------------------------------------------
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            tools=TOOLS,
            messages=messages,
        )

        if verbose:
            print(f"  stop_reason : {response.stop_reason}")
            print(f"  content blocks: {[b.type for b in response.content]}")

        # ---- Check stop reason ----------------------------------------------
        if response.stop_reason == "end_turn":
            # The model is done.  Extract the text from the final response.
            for block in response.content:
                if block.type == "text":
                    if verbose:
                        print(f"\n  FINAL ANSWER:\n  {block.text}")
                    return block.text
            # Edge case: end_turn with no text block (shouldn't happen)
            return ""

        if response.stop_reason == "tool_use":
            # The model wants to call one or more tools.
            # Step A: Add the model's full response to the conversation
            #         (the API requires the assistant turn to be present
            #          before you add the tool_result turn).
            messages.append({"role": "assistant", "content": response.content})

            # Step B: For each tool_use block, execute the tool and collect
            #         tool_result blocks.
            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue  # skip text blocks in this pass

                if verbose:
                    print(f"\n  TOOL CALL  : {block.name}")
                    print(f"  tool_use_id: {block.id}")
                    print(f"  arguments  : {block.input}")

                result_content = execute_tool(block.name, block.input)

                if verbose:
                    # Truncate long file contents in the trace
                    preview = result_content[:200].replace("\n", "\\n")
                    print(f"  tool result: {preview}{'...' if len(result_content) > 200 else ''}")

                # Each result must reference the id from the tool_use block.
                # This is how the API pairs up requests and responses.
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,   # <-- must match block.id
                        "content": result_content,
                    }
                )

            # Step C: Add the tool results as the next user turn, then loop.
            messages.append({"role": "user", "content": tool_results})
            # The loop goes back to the top and makes another API call.

        else:
            # Unexpected stop_reason (e.g. "max_tokens")
            raise RuntimeError(f"Unexpected stop_reason: {response.stop_reason}")


# ---------------------------------------------------------------------------
# Quick smoke-test when run directly
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Create a harmless temp file so the demo works out of the box.
    import tempfile, pathlib

    tmp = pathlib.Path(tempfile.mktemp(suffix=".txt"))
    tmp.write_text("Hello from the test file!\nThe answer is 42.\n")

    print(f"Demo file created at: {tmp}")
    print("Asking the agent to read it...\n")

    answer = run_agent(f"Please read the file at {tmp} and tell me what it says.")

    print(f"\n{'='*60}")
    print("DONE.  Agent returned:")
    print(answer)

    tmp.unlink()  # clean up the temp file
