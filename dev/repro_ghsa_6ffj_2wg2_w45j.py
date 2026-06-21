#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Reproduction of GHSA-6ffj-2wg2-w45j: Deserialization allowlist bypass via
re.match() prefix matching in _match_regexp().

VULNERABILITY
-------------
Before commit 80f1ab4d5a (#66499), ``_match_regexp()`` in
``task-sdk/src/airflow/sdk/serde/__init__.py`` used ``re.match()``
to validate classnames against ``allowed_deserialization_classes_regexp``.

``re.match()`` only anchors at the **start** of the string, so a pattern
like ``airflow\\.models\\.Variable`` also admitted classnames such as
``airflow.models.Variable_Malicious`` — the regex successfully matched
the prefix and ignored the trailing characters.

An attacker who can control the ``__classname__`` field in serialized
XCom data could craft a name that passes the allowlist yet points to an
attacker-controlled module.  ``deserialize()`` then calls
``import_string(classname)``, loading and instantiating the class.

FIX
---
Switch from ``re.match()`` to ``re.fullmatch()`` so the pattern must
match the *entire* classname string.

HOW TO RUN
----------
    python3 dev/repro_ghsa_6ffj_2wg2_w45j.py

OUTPUT
------
Lines marked "VULNERABLE" show classnames the pre-fix code incorrectly
allows.  "FIXED" lines show the same classnames correctly rejected by
``re.fullmatch()``.
"""

from __future__ import annotations

import re
import sys


def match_regexp_vulnerable(classname: str, patterns: list[re.Pattern]) -> bool:
    """Pre-fix behaviour: re.match() — anchors only at start."""
    return any(p.match(classname) is not None for p in patterns)


def match_regexp_fixed(classname: str, patterns: list[re.Pattern]) -> bool:
    """Post-fix behaviour: re.fullmatch() — anchors at both ends."""
    return any(p.fullmatch(classname) is not None for p in patterns)


# Each tuple: (classname, should_be_allowed, description)
CASES: list[tuple[str, bool, str]] = [
    ("airflow.models.Variable", True, "intended exact match"),
    ("airflow.models.Variable_Malicious", False, "suffix bypass"),
    ("airflow.models.VariableSubclass", False, "suffix bypass"),
    ("totally.unrelated.Class", False, "unrelated class"),
]


def main() -> int:
    print("=" * 78)
    print("GHSA-6ffj-2wg2-w45j  —  Deserialization allowlist bypass")
    print("  _match_regexp() used re.match() instead of re.fullmatch()")
    print("=" * 78)

    # The exact scenario: admin restricts to a single class via regexp
    regexp = r"airflow\.models\.Variable"
    patterns = [re.compile(regexp)]
    print(f"\nallowed_deserialization_classes_regexp = {regexp!r}")

    vuln_count = 0
    fixed_count = 0

    print(f"\n  {'classname':45s} {'expect':>6s} {'match':>6s} {'full':>6s}  result")
    print("  " + "-" * 80)

    for classname, expected, _desc in CASES:
        vuln = match_regexp_vulnerable(classname, patterns)
        fixed = match_regexp_fixed(classname, patterns)

        if vuln and not expected:
            tag = "VULNERABLE (re.match allows this)"
            vuln_count += 1
            if not fixed:
                fixed_count += 1
                tag += " → FIXED by fullmatch"
        elif not vuln and expected:
            tag = "BUG — should be allowed"
        else:
            tag = "ok"

        print(f"  {classname:45s} {str(expected):>6s} {str(vuln):>6s} {str(fixed):>6s}  {tag}")

    # Demonstrate the actual attack payload
    print("\n--- Attack payload ---")
    print("  A malicious DAG author stores this XCom value:")
    print('    {"__classname__": "airflow.models.Variable_Malicious",')
    print('     "__version__": 0, "__data__": {}}')
    print()
    print("  With the pre-fix code, _match_regexp() returns True because")
    print(f"  re.compile({regexp!r}).match('airflow.models.Variable_Malicious')")
    m = re.compile(regexp).match("airflow.models.Variable_Malicious")
    print(f"  = {m}  (matched prefix only)")
    print()
    print("  deserialize() then calls import_string('airflow.models.Variable_Malicious'),")
    print("  which imports and instantiates the attacker's class.")

    print("\n" + "=" * 78)
    print(f"RESULT: {vuln_count} bypass(es) found with pre-fix re.match()")
    print(f"        {fixed_count} of those fixed by re.fullmatch()")
    print("=" * 78)

    return 0 if vuln_count > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
