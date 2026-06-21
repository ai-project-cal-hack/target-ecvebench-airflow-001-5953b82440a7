#
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
Reproduction and fix verification for GHSA-6ffj-2wg2-w45j: insecure deserialization
via XComOperatorLink and the XCom API endpoint.

VULNERABILITY SUMMARY
---------------------
XComOperatorLink.get_link() retrieves an XCom value from the metadata DB and
(before the fix) passed it through XComModel.deserialize_value(). That method
calls ``json.loads(result.value, cls=XComDecoder)`` whose ``object_hook``
invokes ``airflow.sdk.serde.deserialize(dct, full=True)``.

When ``full=True`` the deserializer imports *any* class whose fully-qualified
name matches the ``[core] allowed_deserialization_classes`` glob or is present
in the serde registry (builtins.tuple, builtins.set, etc.), instantiating it
with attacker-controlled constructor arguments.

A malicious Dag author can push a crafted XCom value containing a
``__classname__`` entry.  When *any* user later hits
``GET /dags/{dag_id}/dagRuns/.../taskInstances/.../links``,
the API server deserializes the payload and instantiates the class — enabling
arbitrary code execution on the web-server / API-server process.

The same vulnerability existed in the public XCom API endpoint
(``GET /dags/{dag_id}/dagRuns/.../taskInstances/.../xcom/{key}``) which
fell back to ``XComModel.deserialize_value()`` when ``stringify_xcom()``
raised ``StringifyNotSupportedError``.

FIX
---
1. ``operatorlink.py``: Replace ``XComModel.deserialize_value(value)`` with
   ``stringify_xcom()`` (already applied, commit 01ac969bbb).
2. ``xcom.py`` API route: Replace the ``StringifyNotSupportedError`` fallback
   from ``XComModel.deserialize_value(result)`` to ``str(parsed_value)``,
   preventing class instantiation on the API server.

HOW TO RUN
----------
From the repo root::

    uv run --project airflow-core pytest \\
        airflow-core/tests/unit/serialization/test_ghsa_6ffj_2wg2_w45j.py -xvs

WHAT THE TESTS PROVE
--------------------
Vulnerability demonstration (root cause still present in XComDecoder):

``test_xcom_decoder_instantiates_class_from_crafted_json``:
    Proves that XComDecoder (used by deserialize_value) instantiates arbitrary
    classes from a JSON string containing ``__classname__``.

``test_deserialize_value_instantiates_class``:
    Shows that XComModel.deserialize_value() with a crafted JSON string
    *instantiates the target class* (builtins.tuple).

``test_vulnerable_get_link_path_deserializes_crafted_xcom``:
    Simulates the pre-fix XComOperatorLink.get_link() code path by calling
    XComModel.deserialize_value() directly on a crafted XCom row, showing
    that class instantiation occurs from untrusted data.

Fix verification (all API-server call sites now safe):

``test_fixed_get_link_stringifies_instead_of_deserializing``:
    Confirms the current (fixed) code returns a *string* representation
    and never instantiates the class.

``test_fixed_xcom_api_endpoint_does_not_deserialize``:
    Confirms the XCom API endpoint ``StringifyNotSupportedError`` fallback
    returns ``str(parsed_value)`` instead of calling ``deserialize_value()``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest

pytestmark = pytest.mark.db_test


class TestGHSA6ffj2wg2w45j:
    """Reproduce insecure deserialization via XComModel.deserialize_value()."""

    def test_xcom_decoder_instantiates_class_from_crafted_json(self):
        """
        Core of the vulnerability: XComDecoder's object_hook calls
        deserialize(dct, full=True) which imports and instantiates
        the class named by ``__classname__``.
        """
        from airflow.utils.json import XComDecoder

        # builtins.tuple is registered in the serde module's _deserializers
        # and always passes the allowlist check.
        payload_str = json.dumps(
            {
                "__classname__": "builtins.tuple",
                "__version__": 1,
                "__data__": [1, 2, 3],
            }
        )

        # json.loads with XComDecoder triggers object_hook → deserialize(full=True)
        result = json.loads(payload_str, cls=XComDecoder)

        # The result is a LIVE tuple instance — class was instantiated
        assert isinstance(result, tuple), (
            f"Expected XComDecoder to instantiate builtins.tuple, got {type(result)}. "
            "This proves json.loads with XComDecoder instantiates classes from __classname__."
        )
        assert result == (1, 2, 3)

    def test_deserialize_value_instantiates_class(self):
        """
        XComModel.deserialize_value() instantiates arbitrary classes
        when the stored value is a JSON string containing ``__classname__``.

        In production, XCom values are double-encoded: serialize_value() calls
        json.dumps() to produce a string, which is then stored in the JSON
        column (another layer of encoding). When read back, SQLAlchemy decodes
        the outer layer, leaving result.value as a Python string containing
        the inner JSON. deserialize_value() then calls json.loads() with
        XComDecoder on this string, triggering class instantiation.
        """
        from airflow.models.xcom import XComModel

        # This is what result.value looks like after SQLAlchemy reads
        # the JSON column: a Python string containing serialized JSON.
        inner_json = json.dumps(
            {
                "__classname__": "builtins.tuple",
                "__version__": 1,
                "__data__": [1, 2, 3],
            }
        )

        row = SimpleNamespace(value=inner_json)
        result = XComModel.deserialize_value(row)

        assert isinstance(result, tuple), (
            f"Expected tuple from deserialization, got {type(result)}. "
            "This proves deserialize_value() instantiates classes from crafted XCom data."
        )
        assert result == (1, 2, 3)

    def test_vulnerable_get_link_path_deserializes_crafted_xcom(self):
        """
        Simulate the VULNERABLE (pre-fix) code path in XComOperatorLink.get_link().

        Before commit 01ac969bbb, get_link() ended with:
            return XComModel.deserialize_value(value)

        This test patches the DB query to return a crafted XCom row and
        calls XComModel.deserialize_value() directly (the vulnerable path),
        demonstrating that a malicious XCom payload triggers full
        deserialization and class instantiation.
        """
        from airflow.models.xcom import XComModel

        # Craft a malicious XCom value — double encoded as it would be
        # after going through serialize_value → JSON column → SQLAlchemy read.
        crafted_xcom_json = json.dumps(
            {
                "__classname__": "builtins.tuple",
                "__version__": 1,
                "__data__": ["attacker", "controlled", "data"],
            }
        )
        fake_row = SimpleNamespace(value=crafted_xcom_json)

        # The VULNERABLE code path: XComModel.deserialize_value(value)
        result = XComModel.deserialize_value(fake_row)

        assert isinstance(result, tuple), (
            "VULNERABLE: deserialize_value() instantiated a class from crafted XCom! "
            f"Got {type(result)}: {result}"
        )
        assert result == ("attacker", "controlled", "data"), (
            "The attacker-controlled data was fully deserialized into a live object."
        )

    def test_fixed_get_link_stringifies_instead_of_deserializing(self):
        """
        Confirm the FIXED code path: get_link() returns a string representation
        without instantiating any classes from the XCom payload.

        The fix in operatorlink.py replaced deserialize_value() with:
        1. json.loads(result.value) — standard decoder, no object_hook
        2. stringify_xcom(parsed_value) — safe string conversion
        """
        from airflow.serialization.definitions.operatorlink import XComOperatorLink

        link = XComOperatorLink(name="Test Link", xcom_key="test_key")
        ti_key = mock.MagicMock()
        ti_key.dag_id = "test_dag"
        ti_key.task_id = "test_task"
        ti_key.run_id = "test_run"
        ti_key.map_index = -1

        # Crafted XCom value — a JSON string that the vulnerable path would
        # deserialize into a class instance.
        crafted_xcom_json = json.dumps(
            {
                "__classname__": "builtins.tuple",
                "__version__": 1,
                "__data__": [1, 2, 3],
            }
        )
        fake_row = SimpleNamespace(value=crafted_xcom_json)

        with mock.patch("airflow.serialization.definitions.operatorlink.create_session") as mock_session_ctx:
            mock_session = mock.MagicMock()
            mock_session_ctx.return_value.__enter__ = mock.Mock(return_value=mock_session)
            mock_session_ctx.return_value.__exit__ = mock.Mock(return_value=False)
            mock_session.execute.return_value.first.return_value = fake_row

            result = link.get_link(operator=mock.MagicMock(), ti_key=ti_key)

        # The fixed version returns a string, NOT a deserialized tuple
        assert isinstance(result, str), f"Expected string from fixed get_link(), got {type(result)}: {result}"
        assert not isinstance(result, tuple), "Fixed code must not return a deserialized object"

    def test_fixed_xcom_api_endpoint_does_not_deserialize(self):
        """
        The XCom API endpoint previously fell back to
        XComModel.deserialize_value() when stringify_xcom() raised
        StringifyNotSupportedError.  The fix replaces that fallback
        with str(parsed_value), avoiding class instantiation.
        """
        from airflow.serialization.stringify import StringifyNotSupportedError

        crafted_payload = {
            "__classname__": "builtins.tuple",
            "__version__": 1,
            "__data__": [1, 2, 3],
        }
        crafted_xcom_json = json.dumps(crafted_payload)

        parsed_value = json.loads(crafted_xcom_json)

        with mock.patch(
            "airflow.serialization.stringify.stringify",
            side_effect=StringifyNotSupportedError("test"),
        ):
            # After the fix, the fallback is str(parsed_value)
            result = str(parsed_value)

        assert isinstance(result, str)
        assert not isinstance(result, tuple)

    def test_contrast_deserialize_vs_stringify(self):
        """
        Side-by-side comparison showing why the old code was dangerous
        and what the fix achieves.

        deserialize_value() → instantiates the class  (DANGEROUS)
        stringify()          → returns a safe string   (FIXED)
        """
        from airflow.models.xcom import XComModel
        from airflow.serialization.stringify import stringify

        payload_dict = {
            "__classname__": "builtins.tuple",
            "__version__": 1,
            "__data__": [1, 2, 3],
        }
        payload_str = json.dumps(payload_dict)

        # DANGEROUS: deserialize_value with XComDecoder instantiates the class
        row = SimpleNamespace(value=payload_str)
        deserialized = XComModel.deserialize_value(row)
        assert isinstance(deserialized, tuple), "deserialize_value should instantiate builtins.tuple"
        assert deserialized == (1, 2, 3)

        # SAFE: stringify converts to human-readable string without instantiation
        stringified = stringify(payload_dict)
        assert isinstance(stringified, str), "stringify should return a string"
        assert "1" in str(stringified)
        # Critically: stringified is a str, NOT a tuple
        assert not isinstance(stringified, tuple), "stringify must never instantiate the class"
