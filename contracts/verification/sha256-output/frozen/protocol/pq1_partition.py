# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Private PQ1 bounded-partition accounting; no general Kani verdict."""
import hashlib
import json
import math
from pathlib import Path
import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def loads(text):
    return json.loads(text, object_pairs_hook=unique_object)


def read(path):
    return loads(Path(path).read_text())


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def authenticate(pins):
    for path, digest in pins.items():
        require(sha(path) == digest, 'identity changed: ' + path)


FLAGS = ['--no-malloc-may-fail', '--no-undefined-shift-check',
         '--no-signed-overflow-check', '--nan-check',
         '--no-self-loops-to-assumptions', '--no-pointer-primitive-check',
         '--object-bits', '16', '--sat-solver', 'cadical', '--slice-formula',
         '--unwinding-assertions']
PROBES = {'cover', 'reachability_check'}
MARKER = re.compile(r'KANI_CHECK_ID_[^\]\s]+')
BAD_MESSAGE = re.compile(
    r'\bwarning\s*:|\bignoring (?:forall|exists)\b|out of memory|'
    r'solver ran out|bad_alloc|\btimeout\b|time limit|file size limit|'
    r'^(?:error|fatal)(?:\s|:)', re.I | re.M)


def census(text):
    entries = loads(text)
    require(isinstance(entries, list), 'census is not an array')
    inventories = []
    for entry in entries:
        require(isinstance(entry, dict), 'invalid census entry')
        if 'messageType' in entry:
            require(entry['messageType'].upper() not in {'WARNING', 'ERROR'},
                    'census diagnostic')
        require(not BAD_MESSAGE.search(entry.get('messageText', '')),
                'census diagnostic text')
        if 'properties' in entry:
            inventories.append(entry['properties'])
    require(len(inventories) == 1, 'missing or multiple property inventories')
    properties = {}
    for item in inventories[0]:
        for key in ['name', 'class', 'description', 'expression']:
            require(isinstance(item.get(key), str) and item[key], 'missing property ' + key)
        name = item['name']
        require(name not in properties, 'duplicate static property')
        loc = item.get('sourceLocation', {})
        require(loc.get('propertyId') == name and loc.get('propertyClass') == item['class']
                and loc.get('comment') == item['description'], 'property metadata mismatch')
        if not loc.get('file') or not loc.get('function'):
            # CBMC label_properties permits an existing location with an empty
            # function. Keep the six exact generated block_len pointer checks;
            # absent debug locations never exempt them from semantic SUCCESS.
            known = read(Path(__file__).with_name('pq1_partition_anonymous.json'))
            require(item == known.get(name), 'unknown property with absent source identity')
        require(not loc.get('line') or str(loc['line']).isdigit(), 'invalid source line')
        properties[name] = item
    require(0 < len(properties) <= 4096, 'static census outside bound')
    return properties


def groups(properties):
    paired, unmarked = {}, []
    for name, prop in properties.items():
        markers = MARKER.findall(prop['description'])
        require(len(markers) <= 1, 'ambiguous property marker')
        if markers:
            marker = markers[0]
            if prop['class'] == 'reachability_check':
                require(prop['description'] == marker and prop['expression'] == 'FALSE',
                        'malformed reachability probe')
            else:
                require(prop['description'].startswith('[' + marker + '] '),
                        'malformed checked assertion')
            paired.setdefault(marker, []).append(name)
        else:
            require(prop['class'] not in PROBES, 'probe without exact marker')
            unmarked.append([name])
    for members in paired.values():
        require(len(members) == 2, 'missing or ambiguous reachability pair')
        require(sum(properties[n]['class'] == 'reachability_check' for n in members) == 1,
                'pair lacks exactly one reachability probe')
    return [sorted(members) for _, members in sorted(paired.items())] + sorted(unmarked)


def partition(properties, required, capacity=128):
    require(0 < capacity <= 128 and required and set(required) <= set(properties),
            'invalid required roots or capacity')
    all_groups = groups(properties)
    root_group, others = [], []
    for group in all_groups:
        if set(group) & set(required):
            root_group.extend(group)
        else:
            others.append(group)
    require(len(root_group) <= capacity, 'root group exceeds capacity')
    count = math.ceil(len(properties) / capacity)
    require(count <= 32, 'partition count exceeds bound')
    parts = [sorted(root_group)] + [[] for _ in range(count - 1)]

    def probes(part):
        return sum(properties[name]['class'] in PROBES for name in part)

    # Whole groups with costly probes first, spread across the minimum number
    # of bins. A packing failure stops; it never invents more runs or retries.
    for group in sorted(others, key=lambda g: (-probes(g), -len(g), g)):
        choices = [i for i, part in enumerate(parts) if len(part) + len(group) <= capacity]
        require(choices, 'indivisible groups cannot fit frozen partition count')
        index = min(choices, key=lambda i: (probes(parts[i]), len(parts[i]), i))
        parts[index].extend(group)
    validate_partition(properties, parts, required, capacity)
    return parts


def validate_partition(properties, parts, required, capacity=128):
    require(0 < len(parts) <= 32, 'invalid partition count')
    union = []
    owners = {}
    for i, part in enumerate(parts):
        require(0 < len(part) <= capacity, 'empty or oversized partition')
        for name in part:
            require(name in properties and name not in owners, 'unknown or duplicate static ID')
            owners[name] = i
        union.extend(part)
    require(set(union) == set(properties), 'incomplete static union')
    require(set(required) <= set(parts[0]), 'required roots not in first partition')
    for group in groups(properties):
        require(len({owners[name] for name in group}) == 1, 'split reachability pair')


def parse_report(text, properties, selected, exit_code):
    require(exit_code in {0, 10}, 'non-verification exit')
    require(not BAD_MESSAGE.search(text), 'warning or resource diagnostic')
    require(len(selected) == len(set(selected)) and set(selected) <= set(properties),
            'invalid selection')
    require(text.count('** Results:\n') == 1, 'missing or repeated result section')
    body = text.split('** Results:\n', 1)[1]
    summary = re.fullmatch(
        r'(.*?)\n\*\* (\d+) of (\d+) failed(?: \(\d+ iterations?\))?\n'
        r'VERIFICATION (FAILED|SUCCESSFUL)\n', body, re.S)
    require(summary is not None, 'missing or malformed terminal summary')
    rows, dynamic, pending = {}, {}, None
    for line in summary[1].splitlines():
        if pending is None:
            if not line or (not line.startswith('[') and ' function ' in line):
                continue
            require(line.startswith('['), 'unrecognized result line')
            pending = line
        else:
            require(not line.startswith('['), 'unterminated result row')
            pending += '\n' + line
        end = re.search(r': (SUCCESS|FAILURE|UNKNOWN|ERROR|NOT CHECKED|UNREACHABLE)$', pending)
        if end is None:
            continue
        matches = [name for name in selected if pending.startswith('[' + name + '] ')]
        if matches:
            require(len(matches) == 1, 'ambiguous result ID')
            name = matches[0]
            prop = properties[name]
            prefix = '[' + name + '] '
            location = ''
            if prop['sourceLocation'].get('line'):
                location = 'line ' + str(prop['sourceLocation']['line']) + ' '
            # CBMC prints the exact source file when it differs from the
            # current function header. Compare that form against the census;
            # never discard or normalize an arbitrary reported file prefix.
            expected = {prefix + location + prop['description'],
                        prefix + 'file ' + prop['sourceLocation'].get('file', '')
                        + ' ' + location + prop['description']}
            require(pending[:end.start()] in expected,
                    'result description or source line differs')
        else:
            match = re.fullmatch(
                r'\[(.+\.unwind\.(\d+))\] (?:line \d+ )?unwinding assertion loop (\d+)',
                pending[:end.start()])
            require(match is not None and match[2] == match[3], 'unexpected dynamic property')
            name = match[1]
            require(name not in properties, 'unselected static row')
            dynamic[name] = pending[:end.start()]
        require(name not in rows, 'duplicate result row')
        require(end[1] in {'SUCCESS', 'FAILURE'}, 'unresolved result status')
        rows[name] = end[1]
        pending = None
    require(pending is None, 'unfinished result row')
    require(set(rows) == set(selected) | set(dynamic), 'missing selected property')
    failures = sum(status == 'FAILURE' for status in rows.values())
    require(len(rows) == int(summary[3]) and failures == int(summary[2]), 'summary count mismatch')
    require(exit_code == (10 if failures else 0), 'exit/status mismatch')
    require(summary[4] == ('FAILED' if failures else 'SUCCESSFUL'), 'summary polarity mismatch')
    return {'rows': rows, 'dynamic': dynamic}


def semantic_check(properties, report, required, expected_failure=None):
    rows = report['rows']
    require(all(rows[name] == 'SUCCESS' for name in report['dynamic']), 'unwinding failure')
    semantic_failures = {name for name, status in rows.items()
                         if name in properties and properties[name]['class'] not in PROBES
                         and status != 'SUCCESS'}
    expected = {expected_failure} if expected_failure in rows else set()
    require(semantic_failures == expected, 'unexpected semantic result')
    for name, status in required.items():
        if name in rows:
            require(rows[name] == status, 'required root unreachable or wrong')


def aggregate(properties, parts, reports, required, expected_failure=None):
    validate_partition(properties, parts, required)
    require(set(reports) == set(range(len(parts))), 'missing partition receipt')
    union, dynamic = {}, None
    for i, part in enumerate(parts):
        report = reports[i]
        require(set(report['rows']) == set(part) | set(report['dynamic']), 'partition result mismatch')
        semantic_check(properties, report, required, expected_failure)
        if dynamic is None:
            dynamic = report['dynamic']
        require(report['dynamic'] == dynamic, 'dynamic obligation set/metadata differs')
        for name in part:
            require(name not in union, 'duplicated static result')
            union[name] = report['rows'][name]
    require(set(union) == set(properties), 'incomplete result union')
    if expected_failure is not None:
        require(union.get(expected_failure) == 'FAILURE', 'intended negative did not fail')
    return {'static_count': len(union), 'dynamic_count': len(dynamic),
            'partition_count': len(parts), 'complete': True,
            'expected_failure': expected_failure, 'private_adoption': False}
