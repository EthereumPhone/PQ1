"""Selected-only framing and complete composition; raw rows never waive inputs."""
from pathlib import Path
import re
# Imports resolve to the pinned source-only sibling checker copies.
import pq1_promoted_census as partition
from pq1_partition import BAD_MESSAGE


def parse_partial(text, properties, groups, exit_code):
    require = partition.require
    require(exit_code in {0, 10}, 'non-verification partial exit')
    require(isinstance(groups, list) and groups and
            all(isinstance(group, list) and group for group in groups),
            'empty or malformed partial selection')
    selected = [name for group in groups for name in group]
    require(all(isinstance(name, str) for name in selected), 'invalid selected ID')
    require(len(selected) == len(set(selected)), 'overlapping partial selection')
    require(set(selected) < set(properties), 'partial requires a strict static subset')
    require(not BAD_MESSAGE.search(text), 'partial diagnostic')
    lines = text.splitlines(keepends=True)
    index, prefix, reports = 0, [], []
    while index < len(lines) and not lines[index].startswith('PQ1-SCOPED-'):
        prefix.append(lines[index])
        index += 1
    require(index < len(lines) and lines[index] ==
            f'PQ1-SCOPED-PARTIAL-SELECTED {len(selected)} {len(properties)}\n',
            'missing or wrong partial selection counts')
    index += 1
    for group_index, group in enumerate(groups):
        require(index < len(lines) and lines[index] ==
                f'PQ1-SCOPED-GROUP-BEGIN {group_index}\n',
                'missing or out-of-order group begin')
        index += 1
        body = list(prefix) if group_index == 0 else []
        while index < len(lines) and not lines[index].startswith('PQ1-SCOPED-'):
            body.append(lines[index])
            index += 1
        require(index < len(lines), 'missing partial group end')
        end = re.fullmatch(r'PQ1-SCOPED-GROUP-END (\d+) (0|10)\n', lines[index])
        require(end is not None and int(end[1]) == group_index,
                'malformed or out-of-order partial group end')
        report = partition.parse_report(
            ''.join(body), properties, group, int(end[2]))
        require(all(report['rows'][name] == 'SUCCESS' for name in report['dynamic']),
                'partial contains failed unwinding check')
        require(all(report['rows'][name] == 'SUCCESS' for name in group
                    if properties[name]['sourceLocation'].get('propertyFatal')),
                'partial contains failed fatal check')
        reports.append(report)
        index += 1
    require(index < len(lines) and lines[index] ==
            f'PQ1-SCOPED-PARTIAL-COMPLETE {len(groups)} {exit_code}\n',
            'missing or malformed partial completion')
    require(index + 1 == len(lines), 'extra output after partial completion')
    failed = any('FAILURE' in report['rows'].values() for report in reports)
    require(exit_code == (10 if failed else 0), 'partial exit mismatch')
    return reports


def require_selected_maps(actual, expected):
    """Known-failure compatibility data, never a positive-proof predicate."""
    partition.require(actual == expected, 'selected whole-map parity mismatch')


def compose_reports(properties, parts, order, prior, tail, required,
                    expected_failure=None):
    """Semantic aggregation only; callers must first authenticate every receipt."""
    require = partition.require
    partition.validate_partition(properties, parts, required)
    require(order and order[0] == 0 and len(order) == len(parts) and
            set(order) == set(range(len(parts))), 'invalid execution order')
    require(len(tail) == len(order) - 1, 'missing tail group')
    require(isinstance(prior, dict) and 'rows' in prior and 'dynamic' in prior,
            'missing prior report')
    reports = {0: prior, **dict(zip(order[1:], tail))}
    # Fatal checks are mandatory even if someone supplies one as an expected
    # negative. The original semantic negative is never a fatal obligation.
    for index, group in enumerate(parts):
        report = reports[index]
        require(all(report['rows'].get(name) == 'SUCCESS' for name in group
                    if properties[name]['sourceLocation'].get('propertyFatal')),
                'complete composition contains failed or missing fatal check')
    return partition.aggregate(properties, parts, reports, required, expected_failure)
