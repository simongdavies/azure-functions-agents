"""Tests for the sandbox-backed file-tool helpers in ``file_tools.py``.

These cover three layers:

1. **Path translation** -- the public contract that LLM-supplied host
   paths get mapped onto the sandbox's ``/input`` and ``/output``
   mounts, and that anything else is refused.  This is the security
   boundary: the host wrapper never opens a host file -- it just
   translates a path before handing it to the guest, so the translator
   IS the access-control gate.
2. **Snippet builders** -- assert each builder produces valid Python
   that compiles cleanly and embeds parameters via Python literals
   (no f-string injection from LLM input).
3. **Envelope parser** -- the round-trip from the sandbox's
   ``{stdout, stderr, exit_code}`` JSON envelope back to the tool's
   structured payload.
"""
from __future__ import annotations

import json

import pytest

from .conftest import load_modules_under_synthetic_package


# ---------------------------------------------------------------------------
# Module loading -- file_tools relative-imports config, so both need
# to live under the same synthetic parent package.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def file_tools_module():
    modules = load_modules_under_synthetic_package(
        "af_agents_file_tools_test", ["config", "file_tools"]
    )
    return modules["file_tools"]


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop env-var overrides so translator defaults are deterministic."""
    monkeypatch.delenv("AGENT_INPUT_DIR", raising=False)
    monkeypatch.delenv("AGENT_OUTPUT_DIR", raising=False)


# ---------------------------------------------------------------------------
# Path translator: host -> guest rewriting
# ---------------------------------------------------------------------------


def test_host_input_path_rewrites_to_guest_input(file_tools_module) -> None:
    # Default AGENT_INPUT_DIR is /sandbox/in.
    result = file_tools_module.translate_to_guest_path(
        "/sandbox/in/tmp/output-42.json"
    )
    assert result == "/input/tmp/output-42.json"


def test_host_output_path_rewrites_to_guest_output(file_tools_module) -> None:
    result = file_tools_module.translate_to_guest_path(
        "/sandbox/out/report.csv"
    )
    assert result == "/output/report.csv"


def test_overridden_host_dir_is_honoured(
    monkeypatch: pytest.MonkeyPatch, file_tools_module
) -> None:
    monkeypatch.setenv("AGENT_INPUT_DIR", "/var/myapp/in")
    result = file_tools_module.translate_to_guest_path(
        "/var/myapp/in/skills/foo.md"
    )
    assert result == "/input/skills/foo.md"


def test_host_dir_root_alone_maps_to_guest_root(file_tools_module) -> None:
    assert (
        file_tools_module.translate_to_guest_path("/sandbox/in")
        == "/input"
    )
    assert (
        file_tools_module.translate_to_guest_path("/sandbox/out")
        == "/output"
    )


# ---------------------------------------------------------------------------
# Path translator: already-guest paths pass through (after normalization)
# ---------------------------------------------------------------------------


def test_guest_paths_pass_through_unchanged(file_tools_module) -> None:
    assert (
        file_tools_module.translate_to_guest_path("/input/foo.txt")
        == "/input/foo.txt"
    )
    assert (
        file_tools_module.translate_to_guest_path("/output/dir/file.json")
        == "/output/dir/file.json"
    )


def test_redundant_slashes_are_normalized(file_tools_module) -> None:
    assert (
        file_tools_module.translate_to_guest_path("/input//tmp///foo.json")
        == "/input/tmp/foo.json"
    )


def test_dot_segments_are_collapsed(file_tools_module) -> None:
    assert (
        file_tools_module.translate_to_guest_path("/input/./tmp/./foo.json")
        == "/input/tmp/foo.json"
    )


def test_windows_separators_are_normalized(file_tools_module) -> None:
    # On a Windows dev box the LLM might echo a backslash-style path
    # (or a docs example might).  Translator must coerce to POSIX so
    # prefix matching works the same on every host OS.
    assert (
        file_tools_module.translate_to_guest_path(
            "\\sandbox\\in\\tmp\\foo.json"
        )
        == "/input/tmp/foo.json"
    )


# ---------------------------------------------------------------------------
# Path translator: refusals
# ---------------------------------------------------------------------------


def test_arbitrary_host_path_is_refused(file_tools_module) -> None:
    with pytest.raises(file_tools_module.PathTranslationError):
        file_tools_module.translate_to_guest_path("/etc/passwd")


def test_parent_dir_escape_is_refused(file_tools_module) -> None:
    # After posixpath.normpath, this becomes /etc/passwd and is rejected.
    with pytest.raises(file_tools_module.PathTranslationError):
        file_tools_module.translate_to_guest_path(
            "/input/../etc/passwd"
        )


def test_lookalike_prefix_is_refused(file_tools_module) -> None:
    # /sandbox/input-real must NOT be treated as a child of /sandbox/in.
    # This is the prefix-boundary check.
    with pytest.raises(file_tools_module.PathTranslationError):
        file_tools_module.translate_to_guest_path("/sandbox/input-real/x")
    with pytest.raises(file_tools_module.PathTranslationError):
        file_tools_module.translate_to_guest_path("/inputfoo/x")


def test_empty_and_non_string_inputs_refused(file_tools_module) -> None:
    with pytest.raises(file_tools_module.PathTranslationError):
        file_tools_module.translate_to_guest_path("")
    with pytest.raises(file_tools_module.PathTranslationError):
        file_tools_module.translate_to_guest_path(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Snippet builders: must compile and embed parameters as literals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "build, kwargs",
    [
        ("build_view_snippet", {"path": "/input/x", "start_line": 1, "end_line": 10}),
        ("build_view_snippet", {"path": "/input/x", "start_line": None, "end_line": None}),
        ("build_head_snippet", {"path": "/input/x", "lines": 5}),
        ("build_tail_snippet", {"path": "/input/x", "lines": None}),
        (
            "build_grep_snippet",
            {
                "path": "/input/x",
                "pattern": "needle",
                "is_regex": False,
                "ignore_case": True,
                "max_results": 25,
            },
        ),
        (
            "build_jq_snippet",
            {"path": "/input/x.json", "query": ".items[0].name", "max_items": 10},
        ),
    ],
)
def test_snippet_compiles(file_tools_module, build, kwargs) -> None:
    """Every snippet must be syntactically valid Python."""
    builder = getattr(file_tools_module, build)
    snippet = builder(**kwargs)
    compile(snippet, "<snippet>", "exec")


def test_snippet_quotes_evil_path_safely(file_tools_module) -> None:
    """LLM-supplied strings with quotes / newlines must not break the snippet.

    A naive f-string builder would corrupt the snippet if the path
    contained a quote; the repr() path encodes them safely.
    """
    nasty = "/input/' ; print('pwned') ; '#foo\nbar"
    snippet = file_tools_module.build_head_snippet(path=nasty, lines=5)
    # Compile -- if the literal wasn't escaped, this raises SyntaxError.
    compile(snippet, "<snippet>", "exec")
    # And the original literal value must appear, verbatim, somewhere
    # inside the snippet (proof we embedded the value, not a stripped
    # version of it).
    assert repr(nasty) in snippet


# ---------------------------------------------------------------------------
# Envelope parser: success / failure / malformed
# ---------------------------------------------------------------------------


def test_parse_success_envelope(file_tools_module) -> None:
    envelope = json.dumps(
        {
            "stdout": json.dumps({"total_lines": 5, "content": "hi"}),
            "stderr": "",
            "exit_code": 0,
        }
    )
    ok, payload = file_tools_module.parse_snippet_result(envelope)
    assert ok is True
    assert payload == {"total_lines": 5, "content": "hi"}


def test_parse_takes_last_json_line_of_stdout(file_tools_module) -> None:
    """Defensive: tolerate accidental extra prints before the result line."""
    envelope = json.dumps(
        {
            "stdout": 'noise\n{"result": 42}\n',
            "stderr": "",
            "exit_code": 0,
        }
    )
    ok, payload = file_tools_module.parse_snippet_result(envelope)
    assert ok is True
    assert payload == {"result": 42}


def test_parse_nonzero_exit_surfaces_stderr(file_tools_module) -> None:
    envelope = json.dumps(
        {
            "stdout": "",
            "stderr": "Traceback: BOOM",
            "exit_code": 1,
        }
    )
    ok, payload = file_tools_module.parse_snippet_result(envelope)
    assert ok is False
    assert "exited with code 1" in payload["error"]
    assert payload["stderr"] == "Traceback: BOOM"


def test_parse_empty_stdout_when_exit_zero(file_tools_module) -> None:
    envelope = json.dumps({"stdout": "", "stderr": "", "exit_code": 0})
    ok, payload = file_tools_module.parse_snippet_result(envelope)
    assert ok is False
    assert "no stdout" in payload["error"]


def test_parse_non_json_envelope(file_tools_module) -> None:
    ok, payload = file_tools_module.parse_snippet_result("not json")
    assert ok is False
    assert "non-JSON result" in payload["error"]


def test_parse_non_json_stdout_line(file_tools_module) -> None:
    envelope = json.dumps(
        {"stdout": "garbage not json\n", "stderr": "", "exit_code": 0}
    )
    ok, payload = file_tools_module.parse_snippet_result(envelope)
    assert ok is False
    assert "non-JSON stdout" in payload["error"]
