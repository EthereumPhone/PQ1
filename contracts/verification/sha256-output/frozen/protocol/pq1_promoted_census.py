# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Retain raw property records; tolerate only checked-pragma ordering."""
import copy
import json
from pathlib import Path

import pq1_partition as original
from pq1_partition import (FLAGS, aggregate, authenticate, groups, parse_report,
                           partition, read, require, semantic_check, sha,
                           validate_partition, write)


def census(text):
    raw = original.loads(text)
    require(isinstance(raw, list), 'census is not an array')
    normalized = copy.deepcopy(raw)
    known = read(Path(original.__file__).with_name(
        'pq1_partition_anonymous.json'))
    for entry in normalized:
        require(isinstance(entry, dict), 'invalid census entry')
        for item in entry.get('properties', []):
            location = item.get('sourceLocation', {})
            if not location.get('file') or not location.get('function'):
                expected = known.get(item.get('name'))
                if expected is None:
                    # The original strict reader will refuse this shape.
                    continue
                actual_pragmas = location.get('pragma')
                expected_pragmas = expected['sourceLocation']['pragma']
                require(isinstance(actual_pragmas, list)
                        and all(isinstance(value, str) for value in actual_pragmas)
                        and sorted(actual_pragmas) == sorted(expected_pragmas),
                        'anonymous checked-pragma multiset differs')
                # Comparison only: all other fields must still match exactly.
                location['pragma'] = expected_pragmas[:]
    validated = original.census(json.dumps(normalized))
    inventories = [entry['properties']
                   for entry in raw if 'properties' in entry]
    require(len(inventories) == 1, 'census inventory differs')
    result = {item['name']: item for item in inventories[0]}
    require(set(result) == set(validated),
            'validated property identities differ')
    return result
