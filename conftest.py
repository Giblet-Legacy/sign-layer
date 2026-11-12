"""
conftest.py — pytest path setup for P2 Sign

Function:
    Puts this directory and the sibling P1 directory
    (../envelope-layer) on sys.path, located from this file rather
    than the working directory. pytest loads it before collecting
    tests, so test_sign.py (frozen v1, cwd-relative import) and
    test_sign_v2.py both run from any working directory (NOTES D1).
    Contains no functions.

Layer:    P2 — Sign
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_P1 = os.path.join(os.path.dirname(_HERE), "envelope-layer")

for _p in (_P1, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
