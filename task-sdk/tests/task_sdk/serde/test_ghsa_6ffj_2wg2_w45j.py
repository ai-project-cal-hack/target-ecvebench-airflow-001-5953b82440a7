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
"""
Regression tests for GHSA-6ffj-2wg2-w45j: deserialization allowlist bypass
via ``re.match()`` prefix matching in ``_match_regexp()``.

Before the fix (commit 80f1ab4d5a, PR #66499), ``_match_regexp()`` used
``re.match()`` which only anchors at the start of the string.  A pattern
like ``airflow\\.models\\.Variable`` therefore also admitted classnames
such as ``airflow.models.Variable_Malicious``.

The fix switched to ``re.fullmatch()`` so the entire classname must match.

These tests verify the fix is in place: ``_match_regexp()`` must reject
classnames that share an allowed pattern as a prefix but append extra
characters.
"""

from __future__ import annotations

import re

import pytest

from airflow.sdk.serde import (
    _get_patterns,
    _get_regexp_patterns,
    _match,
    _match_glob,
    _match_regexp,
)

from tests_common.test_utils.config import conf_vars


@pytest.fixture
def recalculate_patterns():
    _get_patterns.cache_clear()
    _get_regexp_patterns.cache_clear()
    _match_glob.cache_clear()
    _match_regexp.cache_clear()
    try:
        yield
    finally:
        _get_patterns.cache_clear()
        _get_regexp_patterns.cache_clear()
        _match_glob.cache_clear()
        _match_regexp.cache_clear()


class TestGHSA6ffj2wg2w45j:
    """Regression tests for the _match_regexp prefix-matching bypass."""

    @conf_vars(
        {
            ("core", "allowed_deserialization_classes"): "",
            ("core", "allowed_deserialization_classes_regexp"): r"airflow\.models\.Variable",
        }
    )
    @pytest.mark.usefixtures("recalculate_patterns")
    def test_regexp_rejects_suffixed_classname(self):
        """
        The core vulnerability: a pattern for an exact class must not
        admit classnames that share the pattern as a prefix.
        """
        assert _match("airflow.models.Variable") is True
        assert _match("airflow.models.Variable_Malicious") is False
        assert _match("airflow.models.VariableSubclass") is False

    @conf_vars(
        {
            ("core", "allowed_deserialization_classes"): "",
            ("core", "allowed_deserialization_classes_regexp"): r"airflow\.models\.Variable",
        }
    )
    @pytest.mark.usefixtures("recalculate_patterns")
    def test_vulnerable_code_would_allow_suffix(self):
        """
        Demonstrate that re.match() (the pre-fix behaviour) accepts
        suffixed classnames while re.fullmatch() (the fix) rejects them.
        """
        pattern = re.compile(r"airflow\.models\.Variable")

        # re.match() only anchors at start — suffix passes through
        assert pattern.match("airflow.models.Variable_Malicious") is not None
        assert pattern.match("airflow.models.VariableSubclass") is not None

        # re.fullmatch() anchors at both ends — suffix is rejected
        assert pattern.fullmatch("airflow.models.Variable_Malicious") is None
        assert pattern.fullmatch("airflow.models.VariableSubclass") is None

        # Legitimate class still matches with both
        assert pattern.match("airflow.models.Variable") is not None
        assert pattern.fullmatch("airflow.models.Variable") is not None

    @conf_vars(
        {
            ("core", "allowed_deserialization_classes"): "",
            ("core", "allowed_deserialization_classes_regexp"): r"airflow\.models\..*",
        }
    )
    @pytest.mark.usefixtures("recalculate_patterns")
    def test_namespace_pattern_with_escaped_dot(self):
        """
        A namespace-wide pattern with an escaped dot in the regexp config
        correctly restricts to the ``airflow.models`` namespace.
        """
        assert _match("airflow.models.Variable") is True
        assert _match("airflow.models.DagRun") is True
        assert _match("airflowevil.models.Exploit") is False
        assert _match("airflow_evil.Exploit") is False

    @conf_vars(
        {
            ("core", "allowed_deserialization_classes"): "airflow.*",
            ("core", "allowed_deserialization_classes_regexp"): "",
        }
    )
    @pytest.mark.usefixtures("recalculate_patterns")
    def test_glob_pattern_safe_with_fnmatch(self):
        """
        The glob-based check (fnmatch) treats '.' as a literal character,
        so the default pattern 'airflow.*' does NOT match 'airflowevil'.
        """
        assert _match("airflow.models.Variable") is True
        assert _match("airflowevil") is False
        assert _match("airflowevil.Exploit") is False
        assert _match("airflow_evil.Exploit") is False
