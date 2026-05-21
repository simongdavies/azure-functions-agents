"""Wrap tool results in an untrusted-content envelope.

The Copilot SDK feeds the ``ToolResult.text_result_for_llm`` string
back to the model verbatim.  When that string came from an external
service (MCP server, connector HTTP call, Hyperlight-sandbox stdout),
its contents are not under our control: a malicious or compromised
upstream can embed instructions like "ignore previous prompts and ...".

Wrapping each tool result in a clearly-delimited XML-ish envelope is
a common best practice to help the model distinguish between 
"data from a tool" and "new instructions". We also include the tool's 
name in the envelope so reasoning about which tool the data came from 
stays trivial.

Lives in its own stdlib-only module so the wrapping logic is unit
testable without ``copilot``, ``hyperlight_sandbox``, ``pydantic``,
or any other heavy dep.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "wrap_untrusted_tool_result",
    "OPEN_TAG_TEMPLATE",
    "CLOSE_TAG",
]

# The envelope template.  Two design points:
#
#   1. The tag is XML (``<untrusted-tool-result ...>``) because the
#      Anthropic / OpenAI models have been trained to respect that
#      shape and treat the interior as data.
#
#   2. The closing tag is a *fixed* string -- any literal occurrence of
#      it inside the body is neutralised below.  We do NOT use a
#      random nonce in the closing tag because that would make the
#      envelope opaque to log inspection and audit.
OPEN_TAG_TEMPLATE: Final[str] = '<untrusted-tool-result name="{name}">'
CLOSE_TAG: Final[str] = "</untrusted-tool-result>"

# Tool names that survive into the open tag get sanitised to a
# conservative character class.  This avoids a hostile or buggy tool
# name from breaking out of the open tag via ``"``, ``>``, or other
# attribute-syntax characters.
_TOOL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9_\-]")

# Anything that looks like our envelope literal in the body would
# let an upstream payload pretend to "close" the envelope and then
# start emitting fresh instructions.  Replace the dangerous prefix
# with a visibly-different equivalent that the model can still read
# but cannot confuse with a real close tag.
_OPEN_TAG_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"<\s*/?\s*untrusted-tool-result", flags=re.IGNORECASE
)


def _sanitize_name(name: str) -> str:
    """Strip non-alphanumeric chars from a tool name for the open tag."""
    if not isinstance(name, str):
        name = str(name)
    cleaned = _TOOL_NAME_RE.sub("_", name).strip("_")
    return cleaned or "tool"


def _neutralize_envelope_lookalikes(body: str) -> str:
    """Defang any attempt by the tool body to forge our envelope tags."""
    # Replace either ``<untrusted-tool-result`` or ``</untrusted-tool-result``
    # (with optional whitespace, case-insensitive) with a visibly-different
    # form so the LLM can't be tricked into thinking it's seen a real
    # close tag mid-body.
    return _OPEN_TAG_PREFIX_RE.sub(
        "<_untrusted-tool-result", body
    )


def wrap_untrusted_tool_result(name: str, body: str) -> str:
    """Wrap a tool's text result in the untrusted-content envelope.

    Parameters
    ----------
    name:
        The tool name.  Sanitised to ``[A-Za-z0-9_-]`` for the
        attribute value; falls back to ``"tool"`` if no chars survive.
    body:
        The raw text result.  Any literal occurrences of our envelope
        tag are neutralised so an upstream payload can't break out.

    Returns
    -------
    A single string of the form ``<untrusted-tool-result name="X">BODY</untrusted-tool-result>``
    suitable for the SDK's ``text_result_for_llm`` field.
    """
    if body is None:
        body = ""
    if not isinstance(body, str):
        body = str(body)
    safe_name = _sanitize_name(name)
    safe_body = _neutralize_envelope_lookalikes(body)
    return OPEN_TAG_TEMPLATE.format(name=safe_name) + safe_body + CLOSE_TAG
