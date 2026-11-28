"""Run a bash script from a file instead of passing it to ``bash -c``.

Linux caps a single argument at 128 KiB (MAX_ARG_STRLEN). The installers'
shared blocks are larger than that, so ``bash -c <block>`` fails with E2BIG
on Linux, though it works on macOS.
"""

import atexit
import os
import tempfile

_PATHS = []


@atexit.register
def _cleanup():
    for path in _PATHS:
        try:
            os.unlink(path)
        except OSError:
            pass


def script_argv(bash, script, *args):
    """argv that runs ``script`` with ``args`` as $1...; $0 is the file."""
    fd, path = tempfile.mkstemp(prefix="sigrift-test-", suffix=".sh")
    with os.fdopen(fd, "w") as f:
        f.write(script)
    _PATHS.append(path)
    return [bash, path, *args]
