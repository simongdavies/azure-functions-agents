# Example custom tool supplied by the developer.
#
# Files in this directory are discovered at agent startup, parsed
# host-side with ``ast`` (no execution!), and then their source is
# bootstrapped *inside* the per-session Hyperlight Wasm sandbox.  The
# first non-underscore top-level function in each file becomes a tool
# the LLM can call.
#
# Constraints (enforced by ``custom_tools.py``):
#   * One tool function per file.  The function name becomes the tool
#     name and must be unique across the whole tools/ directory.
#   * Parameter annotations must be drawn from: ``str``, ``int``,
#     ``float``, ``bool``, ``list``, ``dict``, ``tuple``, ``Any``,
#     ``object``, or ``Optional[...]`` thereof.  Custom generics like
#     ``list[int]`` or ``Annotated[...]`` are rejected because they
#     can't be turned into a JSON schema honestly.
#   * The docstring becomes the tool description visible to the LLM,
#     so write it for an AI audience: state when to use the tool and
#     what it returns.
#   * No ``*args`` / ``**kwargs`` / positional-only / keyword-only.
#
# Because the function runs inside the Wasm sandbox, it has access to
# whatever Python stdlib the guest image ships, but NOT to arbitrary
# PyPI packages and NOT to the host filesystem (except via the
# ``/input`` and ``/output`` mounts the host configured).


def word_count(text: str, include_chars: bool = True) -> dict:
    """Count words and lines (and optionally characters) in a block of text.

    Use this whenever the user gives you text and asks "how long is
    this", "how many words", or wants line/word statistics. Returns a
    JSON object with ``words``, ``lines``, and -- when
    ``include_chars`` is true -- ``characters`` and
    ``characters_no_spaces``.

    Args:
        text: The text to analyse.  Required.
        include_chars: When true (the default), also report character
            counts.  Set false if the user only cares about word/line
            counts.
    """
    words = len(text.split())
    lines = len(text.splitlines()) or (1 if text else 0)
    result = {"words": words, "lines": lines}
    if include_chars:
        result["characters"] = len(text)
        result["characters_no_spaces"] = sum(1 for ch in text if not ch.isspace())
    return result
