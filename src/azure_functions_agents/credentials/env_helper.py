"""Environment-variable credential resolver.

The ``env:VAR_NAME`` source-type returns the *literal* value of the
named environment variable.  Empty / missing values are treated as
fatal: a misconfigured deployment is safer-failing than silently
sending a credentialed request with no Authorization header (which
would either succeed against an anonymous endpoint -- exfil risk --
or 401 with a confusing error trail).

The variable name has already been validated by the parser
(:func:`azure_functions_agents.credentials.parse_source`); this
module trusts that contract and limits itself to the runtime read.
"""

from __future__ import annotations

import os

from . import CredentialResolveError

__all__ = ["read_required"]


def read_required(var_name: str) -> str:
    """Return the value of the ``var_name`` environment variable.

    Raises :class:`CredentialResolveError` if the variable is unset
    or empty.  The error message names the variable so operators can
    debug, but the value itself is never echoed.
    """
    value = os.environ.get(var_name)
    if not value:
        raise CredentialResolveError(
            f"credentials: env var {var_name!r} is required for source"
            f" 'env:{var_name}' but is unset or empty"
        )
    return value
