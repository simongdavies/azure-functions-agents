"""Tests for ``custom_tools.py``.

The module is the host-side bridge between developer-supplied ``.py``
files in ``<app_root>/tools/`` and the per-session Hyperlight sandbox.
Per the v0.8 RFC, the host never parses developer content --
introspection happens via :func:`ast.parse` *inside* an ephemeral
Hyperlight VM.

These tests cover the host bridge end-to-end, but they substitute a
**CPython-based fake sandbox runner** for the real Hyperlight VM.
This is sound because the discovery snippet:

* is host-controlled framework code (no developer bytes parsed on
  the host),
* imports only stdlib modules (``ast``, ``json``) -- the same surface
  the WASM Python guest supports,
* emits a single JSON line on stdout.

So CPython is a faithful stand-in for the guest interpreter for the
discovery snippet's behaviour.  Real-Hyperlight integration is
covered by the sandbox suite.

Coverage:

1. **Schema extraction** -- every whitelisted annotation maps to the
   right JSON schema, ``Optional[X]`` unwraps to ``X``, and anything
   outside the whitelist is refused.
2. **Tool selection** -- first non-underscore top-level function wins,
   ``_``-prefixed and missing functions are skipped, name collisions
   across files are detected.
3. **Discovery semantics** -- missing tools dir, explicit module list,
   opt-out empty list, invalid module names, path traversal.
4. **Bootstrap shape** -- contains the source verbatim, has the
   ``# --- custom tool: <name> ---`` separator, ordering matches
   the spec list.
5. **Dispatch snippet** -- builds, compiles, name-mangled namespace is
   self-contained, args round-trip through JSON.
6. **Discovery plumbing** -- snippet compiles, envelope parsing
   rejects malformed output, file-size cap enforced, sandbox-runner
   failures degrade gracefully to an empty toolset.
"""
from __future__ import annotations

import contextlib
import io
import json
import textwrap
from pathlib import Path
from typing import Any, Dict, List

import pytest

from .conftest import load_modules_under_synthetic_package


# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def loaded_modules():
    """Load ``custom_tools`` + its dep ``config`` under one synthetic
    package so the relative ``from .config import get_app_root`` inside
    ``custom_tools`` resolves to the same module instance the tests
    poke via :func:`set_app_root`.
    """
    return load_modules_under_synthetic_package(
        "af_agents_custom_tools_test", ["config", "custom_tools"]
    )


@pytest.fixture(scope="module")
def custom_tools_module(loaded_modules):
    return loaded_modules["custom_tools"]


@pytest.fixture(scope="module")
def config_module(loaded_modules):
    return loaded_modules["config"]


def _cpython_discovery_runner(snippet: str) -> str:
    """Run the discovery snippet under CPython and return its stdout.

    Used as the test substitute for the real Hyperlight-backed
    runner.  See the module docstring for why this is sound.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # ``snippet`` is host-controlled framework code from
        # ``custom_tools.build_discovery_snippet`` -- never developer
        # content -- so ``exec`` is safe here.
        exec(snippet, {})  # noqa: S102 - intentional, host-generated code.
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _inject_cpython_runner(custom_tools_module):
    """Monkey-patch :func:`custom_tools.discover_custom_tools` to
    default ``sandbox_runner`` to :func:`_cpython_discovery_runner`.

    Without this, every existing test would have to thread the runner
    through manually.  An autouse fixture keeps the test bodies
    focused on what they're actually checking.  Individual tests can
    still pass an explicit ``sandbox_runner=`` kwarg to override
    (e.g. the "runner raises" test below).
    """
    original = custom_tools_module.discover_custom_tools

    def _wrapped(
        explicit_modules=None,
        *,
        sandbox_runner=None,
    ):
        runner = (
            sandbox_runner
            if sandbox_runner is not None
            else _cpython_discovery_runner
        )
        return original(explicit_modules, sandbox_runner=runner)

    custom_tools_module.discover_custom_tools = _wrapped
    try:
        yield
    finally:
        custom_tools_module.discover_custom_tools = original


@pytest.fixture
def tools_root(tmp_path: Path, config_module) -> Path:
    """Create ``<tmp>/tools/`` and point ``get_app_root`` at ``<tmp>``."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    previous = config_module._app_root
    config_module.set_app_root(tmp_path)
    try:
        yield tools_dir
    finally:
        config_module._app_root = previous


def _write_tool(tools_root: Path, filename: str, source: str) -> Path:
    path = tools_root / filename
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Schema extraction
# ---------------------------------------------------------------------------


class TestAnnotationToSchema:
    @pytest.mark.parametrize(
        "annotation,expected_type",
        [
            ("str", "string"),
            ("int", "integer"),
            ("float", "number"),
            ("bool", "boolean"),
            ("list", "array"),
            ("dict", "object"),
            ("tuple", "array"),
        ],
    )
    def test_basic_types(
        self,
        annotation: str,
        expected_type: str,
        tools_root: Path,
        custom_tools_module,
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            f"""
            def my_tool(arg: {annotation}) -> dict:
                '''docstring'''
                return {{}}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert len(toolset.specs) == 1
        props = toolset.specs[0].parameters_schema["properties"]
        assert props["arg"] == {"type": expected_type}

    def test_capitalised_typing_aliases(
        self, tools_root: Path, custom_tools_module
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            """
            from typing import List, Dict, Tuple
            def my_tool(a: List, b: Dict, c: Tuple) -> dict:
                '''d'''
                return {}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert len(toolset.specs) == 1
        props = toolset.specs[0].parameters_schema["properties"]
        assert props == {
            "a": {"type": "array"},
            "b": {"type": "object"},
            "c": {"type": "array"},
        }

    def test_any_and_object_are_unconstrained(
        self, tools_root: Path, custom_tools_module
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            """
            from typing import Any
            def my_tool(a: Any, b: object) -> dict:
                '''d'''
                return {}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert len(toolset.specs) == 1
        props = toolset.specs[0].parameters_schema["properties"]
        # Empty schema fragment -> "no type constraint".
        assert props["a"] == {}
        assert props["b"] == {}

    def test_missing_annotation_is_unconstrained(
        self, tools_root: Path, custom_tools_module
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            """
            def my_tool(arg) -> dict:
                '''d'''
                return {}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert len(toolset.specs) == 1
        assert toolset.specs[0].parameters_schema["properties"]["arg"] == {}

    def test_optional_unwraps_inner_type(
        self, tools_root: Path, custom_tools_module
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            """
            from typing import Optional
            def my_tool(arg: Optional[int]) -> dict:
                '''d'''
                return {}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert len(toolset.specs) == 1
        assert (
            toolset.specs[0].parameters_schema["properties"]["arg"]
            == {"type": "integer"}
        )

    def test_union_with_none_unwraps_inner_type(
        self, tools_root: Path, custom_tools_module
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            """
            from typing import Union
            def my_tool(arg: Union[str, None]) -> dict:
                '''d'''
                return {}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert len(toolset.specs) == 1
        assert (
            toolset.specs[0].parameters_schema["properties"]["arg"]
            == {"type": "string"}
        )

    def test_unsupported_annotation_skips_tool(
        self,
        tools_root: Path,
        custom_tools_module,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _write_tool(
            tools_root,
            "t.py",
            """
            class Custom: ...
            def my_tool(arg: Custom) -> dict:
                '''d'''
                return {}
            """,
        )
        with caplog.at_level("WARNING"):
            toolset = custom_tools_module.discover_custom_tools()
        assert toolset.specs == ()
        assert any("unsupported annotation" in rec.message for rec in caplog.records)

    def test_parameterised_generic_skips_tool(
        self, tools_root: Path, custom_tools_module
    ) -> None:
        # ``List[int]`` is a subscript with content other than Optional/Union;
        # we refuse it because the JSON schema we'd generate would lie.
        _write_tool(
            tools_root,
            "t.py",
            """
            from typing import List
            def my_tool(arg: List[int]) -> dict:
                '''d'''
                return {}
            """,
        )
        toolset = custom_tools_module.discover_custom_tools()
        assert toolset.specs == ()


# ---------------------------------------------------------------------------
# Required / optional inference
# ---------------------------------------------------------------------------


def test_required_vs_optional_from_defaults(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "t.py",
        """
        def my_tool(required: str, optional: int = 7) -> dict:
            '''d'''
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools()
    schema = toolset.specs[0].parameters_schema
    assert schema["required"] == ["required"]
    assert "optional" in schema["properties"]


# ---------------------------------------------------------------------------
# Tool selection: first non-underscore function in the file
# ---------------------------------------------------------------------------


def test_first_non_underscore_function_wins(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "t.py",
        """
        def _helper():
            return 1
        def public_tool() -> dict:
            '''this is the one'''
            return {}
        def other_function() -> dict:
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools()
    assert len(toolset.specs) == 1
    assert toolset.specs[0].name == "public_tool"
    assert toolset.specs[0].description == "this is the one"


def test_underscore_only_file_yields_no_tools(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "t.py",
        """
        def _helper():
            return 1
        """,
    )
    toolset = custom_tools_module.discover_custom_tools()
    assert toolset.specs == ()
    assert toolset.bootstrap_code == ""


def test_syntax_error_file_is_skipped(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _write_tool(
        tools_root,
        "broken.py",
        """
        def my_tool(
        """,
    )
    _write_tool(
        tools_root,
        "good.py",
        """
        def good_tool() -> dict:
            '''ok'''
            return {}
        """,
    )
    with caplog.at_level("WARNING"):
        toolset = custom_tools_module.discover_custom_tools()
    assert [s.name for s in toolset.specs] == ["good_tool"]
    assert any("SyntaxError" in rec.message for rec in caplog.records)


def test_varargs_or_kwargs_are_rejected(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _write_tool(
        tools_root,
        "t.py",
        """
        def my_tool(*args, **kwargs) -> dict:
            '''d'''
            return {}
        """,
    )
    with caplog.at_level("WARNING"):
        toolset = custom_tools_module.discover_custom_tools()
    assert toolset.specs == ()
    assert any("unsupported parameter kinds" in rec.message for rec in caplog.records)


def test_keyword_only_is_rejected(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "t.py",
        """
        def my_tool(*, key: int) -> dict:
            '''d'''
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools()
    assert toolset.specs == ()


# ---------------------------------------------------------------------------
# Cross-file behaviour
# ---------------------------------------------------------------------------


def test_name_collision_keeps_first_and_warns(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _write_tool(
        tools_root,
        "a.py",
        """
        def shared() -> dict:
            '''first'''
            return {'src': 'a'}
        """,
    )
    _write_tool(
        tools_root,
        "b.py",
        """
        def shared() -> dict:
            '''second'''
            return {'src': 'b'}
        """,
    )
    with caplog.at_level("WARNING"):
        toolset = custom_tools_module.discover_custom_tools()
    assert len(toolset.specs) == 1
    assert toolset.specs[0].source_module == "a"
    assert any("collides" in rec.message for rec in caplog.records)


def test_underscore_files_are_not_auto_discovered(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "_helpers.py",
        """
        def helper() -> dict:
            '''should not show up'''
            return {}
        """,
    )
    _write_tool(
        tools_root,
        "real.py",
        """
        def real_tool() -> dict:
            '''d'''
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools()
    assert [s.name for s in toolset.specs] == ["real_tool"]


# ---------------------------------------------------------------------------
# Discovery entry-point semantics
# ---------------------------------------------------------------------------


def test_missing_tools_dir_returns_empty(
    tmp_path: Path, custom_tools_module, config_module
) -> None:
    previous = config_module._app_root
    config_module.set_app_root(tmp_path)  # tmp_path has no ``tools/``
    try:
        toolset = custom_tools_module.discover_custom_tools()
    finally:
        config_module._app_root = previous
    assert toolset.specs == ()
    assert toolset.bootstrap_code == ""


def test_explicit_empty_list_opts_out(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "t.py",
        """
        def t() -> dict:
            '''d'''
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools(explicit_modules=[])
    assert toolset.specs == ()


def test_explicit_module_list_filters(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "alpha.py",
        """
        def alpha() -> dict:
            '''a'''
            return {}
        """,
    )
    _write_tool(
        tools_root,
        "beta.py",
        """
        def beta() -> dict:
            '''b'''
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools(
        explicit_modules=["beta"]
    )
    assert [s.name for s in toolset.specs] == ["beta"]


def test_invalid_module_name_is_rejected(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Path traversal attempt -- module name with path separators must
    # never resolve to a file outside <tools_dir>.
    with caplog.at_level("WARNING"):
        toolset = custom_tools_module.discover_custom_tools(
            explicit_modules=["../etc/passwd", "good name", "1bad"]
        )
    assert toolset.specs == ()
    # All three should produce a "rejecting tool module" warning.
    rejections = [
        rec for rec in caplog.records if "rejecting tool module" in rec.message
    ]
    assert len(rejections) == 3


def test_missing_explicit_module_warns(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING"):
        toolset = custom_tools_module.discover_custom_tools(
            explicit_modules=["ghost"]
        )
    assert toolset.specs == ()
    assert any("file " in rec.message and "not found" in rec.message
               for rec in caplog.records)


# ---------------------------------------------------------------------------
# Bootstrap content
# ---------------------------------------------------------------------------


def test_bootstrap_contains_source_verbatim_with_separator(
    tools_root: Path, custom_tools_module
) -> None:
    source = textwrap.dedent(
        """
        def magic() -> dict:
            '''d'''
            return {'value': 42}
        """
    ).lstrip()
    (tools_root / "magic.py").write_text(source, encoding="utf-8")

    toolset = custom_tools_module.discover_custom_tools()
    assert "# --- custom tool: magic ---" in toolset.bootstrap_code
    # The verbatim function definition must appear in the bootstrap so
    # the guest's exec() lands it in globals().
    assert "def magic() -> dict:" in toolset.bootstrap_code
    assert "return {'value': 42}" in toolset.bootstrap_code


def test_bootstrap_is_empty_when_no_tools_accepted(
    tools_root: Path, custom_tools_module
) -> None:
    _write_tool(
        tools_root,
        "broken.py",
        """
        def my_tool(arg: complex) -> dict:
            '''rejected: complex not whitelisted'''
            return {}
        """,
    )
    toolset = custom_tools_module.discover_custom_tools()
    assert toolset.specs == ()
    assert toolset.bootstrap_code == ""


# ---------------------------------------------------------------------------
# Dispatch snippet
# ---------------------------------------------------------------------------


def _build_spec(custom_tools_module, params: List[str]) -> Any:
    """Hand-build a spec for snippet tests so they don't depend on
    end-to-end discovery."""
    return custom_tools_module.CustomToolSpec(
        name="my_tool",
        description="doc",
        parameters_schema={
            "type": "object",
            "properties": {p: {} for p in params},
            "required": params,
            "additionalProperties": False,
        },
        source_module="my_tool",
        parameter_names=tuple(params),
    )


def test_dispatch_snippet_compiles(custom_tools_module) -> None:
    spec = _build_spec(custom_tools_module, ["a", "b"])
    snippet = custom_tools_module.build_dispatch_snippet(
        spec, {"a": "hello", "b": 7}
    )
    # If this raises SyntaxError the snippet would crash inside the
    # guest with a confusing error -- catch it on the host instead.
    compile(snippet, "<dispatch>", "exec")


def test_dispatch_snippet_round_trips_args_via_json(
    custom_tools_module,
) -> None:
    spec = _build_spec(custom_tools_module, ["text"])
    tricky = {
        "text": "single ' double \" newline\nbackslash \\ unicode \u2603"
    }
    snippet = custom_tools_module.build_dispatch_snippet(spec, tricky)

    # Run the snippet under a controlled namespace to verify the args
    # round-trip exactly through the JSON encode/decode without leaking
    # into Python's literal grammar.
    captured: Dict[str, Any] = {}

    def my_tool(**kwargs: Any) -> Dict[str, Any]:
        captured.update(kwargs)
        return {"echo": kwargs}

    namespace: Dict[str, Any] = {"my_tool": my_tool}
    exec(snippet, namespace)  # noqa: S102 - intentional, this is a test.

    assert captured == tricky


def test_dispatch_snippet_emits_result_envelope(
    custom_tools_module, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = _build_spec(custom_tools_module, ["value"])
    snippet = custom_tools_module.build_dispatch_snippet(
        spec, {"value": 99}
    )

    def my_tool(value: int) -> Dict[str, Any]:
        return {"got": value}

    namespace: Dict[str, Any] = {"my_tool": my_tool}
    exec(snippet, namespace)  # noqa: S102
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert payload == {"result": {"got": 99}}


def test_dispatch_snippet_emits_error_envelope_on_exception(
    custom_tools_module, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = _build_spec(custom_tools_module, [])
    snippet = custom_tools_module.build_dispatch_snippet(spec, {})

    def my_tool() -> None:
        raise ValueError("kaboom")

    namespace: Dict[str, Any] = {"my_tool": my_tool}
    exec(snippet, namespace)  # noqa: S102
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert payload == {"error": "ValueError: kaboom"}


def test_dispatch_snippet_cleans_up_helper_globals(
    custom_tools_module,
) -> None:
    spec = _build_spec(custom_tools_module, [])
    snippet = custom_tools_module.build_dispatch_snippet(spec, {})

    def my_tool() -> Dict[str, int]:
        return {"ok": 1}

    namespace: Dict[str, Any] = {"my_tool": my_tool}
    exec(snippet, namespace)  # noqa: S102

    leaked = [k for k in namespace if k.startswith("__azfa_tool_call_")]
    assert leaked == [], f"snippet leaked helper globals: {leaked}"


def test_dispatch_snippet_serialises_non_json_with_default_str(
    custom_tools_module, capsys: pytest.CaptureFixture[str]
) -> None:
    """Return values that aren't JSON-native should degrade via str()
    rather than crashing the dispatch."""
    spec = _build_spec(custom_tools_module, [])
    snippet = custom_tools_module.build_dispatch_snippet(spec, {})

    class Custom:
        def __str__(self) -> str:
            return "custom-repr"

    def my_tool() -> Custom:
        return Custom()

    namespace: Dict[str, Any] = {"my_tool": my_tool, "Custom": Custom}
    exec(snippet, namespace)  # noqa: S102
    out = capsys.readouterr().out.strip()
    payload = json.loads(out)
    assert payload == {"result": "custom-repr"}


# ---------------------------------------------------------------------------
# CustomToolSpec ordering matches bootstrap ordering
# ---------------------------------------------------------------------------


def test_specs_ordering_is_sorted_filename(
    tools_root: Path, custom_tools_module
) -> None:
    for name in ("zulu.py", "alpha.py", "mike.py"):
        _write_tool(
            tools_root,
            name,
            f"""
            def {name.removesuffix('.py')}() -> dict:
                '''d'''
                return {{}}
            """,
        )
    toolset = custom_tools_module.discover_custom_tools()
    assert [s.name for s in toolset.specs] == ["alpha", "mike", "zulu"]
    # Bootstrap separators appear in the same order.
    pos_alpha = toolset.bootstrap_code.find("custom tool: alpha")
    pos_mike = toolset.bootstrap_code.find("custom tool: mike")
    pos_zulu = toolset.bootstrap_code.find("custom tool: zulu")
    assert 0 <= pos_alpha < pos_mike < pos_zulu


# ---------------------------------------------------------------------------
# Discovery plumbing (in-sandbox parsing)
# ---------------------------------------------------------------------------


def test_build_discovery_snippet_compiles(custom_tools_module) -> None:
    """The snippet must be valid Python before we ship it to the guest.

    Catching SyntaxError on the host gives a clean error message;
    failing inside the Wasm VM would surface a less actionable
    ``exit_code != 0`` from :func:`Sandbox.run`.
    """
    snippet = custom_tools_module.build_discovery_snippet(
        {"foo": "def foo(a: str) -> dict:\n    '''d'''\n    return {}\n"}
    )
    compile(snippet, "<discovery>", "exec")


def test_build_discovery_snippet_handles_tricky_string_content(
    custom_tools_module,
) -> None:
    """Developer sources containing single/double quotes, backslashes,
    and non-ASCII characters must round-trip through the JSON literal
    embedding without breaking the host's Python parser or the
    guest's JSON decoder.
    """
    tricky_source = (
        "def my_tool(a: str) -> dict:\n"
        "    \"\"\"single ' double \\\" newline\\nbackslash \\\\ snowman \u2603\"\"\"\n"
        "    return {'a': a}\n"
    )
    snippet = custom_tools_module.build_discovery_snippet(
        {"tricky": tricky_source}
    )
    # 1. Host-side: it's compilable.
    compile(snippet, "<discovery>", "exec")
    # 2. Guest-side: running it produces a usable envelope.
    stdout = _cpython_discovery_runner(snippet)
    parsed = custom_tools_module.parse_discovery_output(stdout)
    assert "tricky" in parsed
    assert parsed["tricky"]["accepted"] is True


class TestParseDiscoveryOutput:
    def test_rejects_invalid_json(self, custom_tools_module) -> None:
        with pytest.raises(ValueError, match="not valid JSON"):
            custom_tools_module.parse_discovery_output("not json at all")

    def test_rejects_non_object_envelope(self, custom_tools_module) -> None:
        with pytest.raises(ValueError, match="must be a JSON object"):
            custom_tools_module.parse_discovery_output("[1, 2, 3]")

    def test_rejects_wrong_version(self, custom_tools_module) -> None:
        bad = json.dumps({"version": 99, "results": []})
        with pytest.raises(ValueError, match="version"):
            custom_tools_module.parse_discovery_output(bad)

    def test_rejects_missing_results(self, custom_tools_module) -> None:
        bad = json.dumps({"version": 1})
        with pytest.raises(ValueError, match="results"):
            custom_tools_module.parse_discovery_output(bad)

    def test_skips_malformed_entries_silently(
        self, custom_tools_module
    ) -> None:
        # Entries that aren't a dict with a string ``module`` are
        # ignored.  Real guests never emit these; this just bounds the
        # blast radius if the snippet's format ever drifts.
        ok = {"module": "ok", "accepted": True, "spec": {}}
        envelope = json.dumps(
            {"version": 1, "results": [ok, "not a dict", {"no_module": 1}]}
        )
        out = custom_tools_module.parse_discovery_output(envelope)
        assert list(out.keys()) == ["ok"]


def test_oversized_tool_file_is_skipped(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A pathological tool file must be skipped before its bytes ever
    reach the discovery sandbox.  Defence in depth -- the guest has
    its own heap limits but we don't want to rely on them here.
    """
    cap = custom_tools_module._MAX_CUSTOM_TOOL_BYTES
    # cap+1 bytes of valid-but-oversized Python.
    padding = "x = '" + ("a" * (cap + 1)) + "'\n"
    _write_tool(tools_root, "oversized.py", padding)
    _write_tool(
        tools_root,
        "small.py",
        """
        def small() -> dict:
            '''d'''
            return {}
        """,
    )
    with caplog.at_level("WARNING"):
        toolset = custom_tools_module.discover_custom_tools()
    assert [s.name for s in toolset.specs] == ["small"]
    assert any(
        "exceeds the discovery size cap" in rec.message
        for rec in caplog.records
    )


def test_sandbox_runner_failure_returns_empty_toolset(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the discovery sandbox itself fails to run (Hyperlight error,
    timeout, ...), we register no custom tools rather than half-load
    the agent.  The Function App must still start so other agents
    keep working.
    """
    _write_tool(
        tools_root,
        "t.py",
        """
        def t() -> dict:
            '''d'''
            return {}
        """,
    )

    def _exploding_runner(snippet: str) -> str:
        raise RuntimeError("discovery sandbox blew up")

    with caplog.at_level("ERROR"):
        toolset = custom_tools_module.discover_custom_tools(
            sandbox_runner=_exploding_runner,
        )
    assert toolset.specs == ()
    assert toolset.bootstrap_code == ""
    assert any(
        "discovery sandbox failed" in rec.message for rec in caplog.records
    )


def test_sandbox_runner_returns_malformed_output(
    tools_root: Path,
    custom_tools_module,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A runner that returns junk (decoded somehow but not valid
    envelope JSON) must degrade to an empty toolset and log loudly.
    """
    _write_tool(
        tools_root,
        "t.py",
        """
        def t() -> dict:
            '''d'''
            return {}
        """,
    )

    def _garbage_runner(snippet: str) -> str:
        return "totally not JSON"

    with caplog.at_level("ERROR"):
        toolset = custom_tools_module.discover_custom_tools(
            sandbox_runner=_garbage_runner,
        )
    assert toolset.specs == ()
    assert any(
        "discovery output unparseable" in rec.message
        for rec in caplog.records
    )


def test_discovery_runs_in_one_sandbox_invocation(
    tools_root: Path,
    custom_tools_module,
) -> None:
    """Critical efficiency invariant: discovery must batch every tool
    file into a single ``sandbox_runner`` call, not one call per file.
    Discovery runs at Functions startup and an N-VM-per-tool design
    would slow cold-start linearly with the number of custom tools.
    """
    for name in ("a.py", "b.py", "c.py"):
        _write_tool(
            tools_root,
            name,
            f"""
            def {name.removesuffix('.py')}() -> dict:
                '''d'''
                return {{}}
            """,
        )

    call_count = 0

    def _counting_runner(snippet: str) -> str:
        nonlocal call_count
        call_count += 1
        return _cpython_discovery_runner(snippet)

    toolset = custom_tools_module.discover_custom_tools(
        sandbox_runner=_counting_runner,
    )
    assert [s.name for s in toolset.specs] == ["a", "b", "c"]
    assert call_count == 1


def test_discovery_skips_sandbox_when_nothing_to_parse(
    tools_root: Path,
    custom_tools_module,
) -> None:
    """When the developer opts out (or the tools dir is empty), we
    must NOT spin up a discovery sandbox.  Cold-start tax is real;
    no work for agents without custom tools is the whole point.
    """
    runner_called = False

    def _runner(snippet: str) -> str:
        nonlocal runner_called
        runner_called = True
        return _cpython_discovery_runner(snippet)

    toolset = custom_tools_module.discover_custom_tools(
        explicit_modules=[],
        sandbox_runner=_runner,
    )
    assert toolset.specs == ()
    assert runner_called is False
