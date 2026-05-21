"""Smoke test: verify whether the Hyperlight Python guest preserves
module-level globals across successive ``Sandbox.run()`` calls.

If the guest builds a fresh globals dict on every call (as the current
``Executor.run`` implementation literally does), then a ``def`` in run #1
will be gone by run #2 -> NameError.  If the guest persists globals on
the same Executor instance, the second run will resolve ``hello`` and
print 'world'.

Run from the azure-functions-agents repo root:

    .venv\\Scripts\\python.exe scratch\\smoke_guest_globals.py
"""

from __future__ import annotations

import sys
import textwrap

from hyperlight_sandbox import Sandbox


def main() -> int:
    sandbox = Sandbox(backend="wasm", module="python_guest.path")

    # Warmup so first-call init noise doesn't pollute stderr below.
    sandbox.run("None")

    define = sandbox.run("def hello():\n    return 'world'\n")
    print("--- run #1 (def hello) ---")
    print(f"exit_code={define.exit_code}")
    print(f"stdout={define.stdout!r}")
    print(f"stderr={define.stderr!r}")

    invoke = sandbox.run("print(hello())\n")
    print("--- run #2 (print(hello())) ---")
    print(f"exit_code={invoke.exit_code}")
    print(f"stdout={invoke.stdout!r}")
    print(f"stderr={invoke.stderr!r}")

    # Verdict
    bug = invoke.exit_code != 0 and "NameError" in invoke.stderr
    fixed = invoke.exit_code == 0 and invoke.stdout.strip() == "world"

    print()
    if fixed:
        print("VERDICT: globals PERSIST across run() -- bug is fixed.")
        return 0
    if bug:
        print(
            textwrap.dedent(
                """\
                VERDICT: globals are RESET on every run() -- bug reproduced.

                The first run defined ``hello`` into a temporary dict
                that the guest's Executor.run() throws away when the
                method returns.  The second run gets a fresh dict and
                cannot see ``hello``.
                """
            )
        )
        return 2
    print("VERDICT: indeterminate -- inspect output above.")
    return 3


if __name__ == "__main__":
    sys.exit(main())
