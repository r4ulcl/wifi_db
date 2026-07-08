'''pytest bootstrap: the tests import the top-level project modules (`utils`,
`wifi_db`) and the sibling `test_base` helper. pytest loads this conftest before
importing the test modules in tests/, so put the repo root and this tests/
directory on sys.path here, making those imports resolve no matter how pytest is
invoked (`pytest`, `python -m pytest`, from any cwd).'''
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))   # tests/
_ROOT = os.path.dirname(_HERE)                        # repo root
for _path in (_ROOT, _HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)
