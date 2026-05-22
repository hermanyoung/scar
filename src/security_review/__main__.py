"""Allow `python -m security_review` invocation."""
import sys

from security_review import MODULE_ROOT

# scar.py lives at the project root, not inside the package
sys.path.insert(0, str(MODULE_ROOT))

from scar import cli

cli()
