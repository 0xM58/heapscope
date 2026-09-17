"""Let ``python -m heapscope`` work, not just the installed console script.

Without this, looking at a heap from a fresh checkout means either installing
the package first or remembering to type ``python -m heapscope.cli``. Neither is
something you should have to know just to open the viewer.
"""

import sys

from .cli import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
