"""Shared utilities for benchmark evaluation

Common functions used across all benchmark types (synthetic, BugsInPy, CVE).
"""

import re


def reverse_diff(bug_patch):
    """Reverses a bug patch to show bug introduction instead of fix

    Args:
        bug_patch: The patch string showing the bug fix

    Returns:
        Reversed patch showing the bug being introduced
    """
    lines = bug_patch.split('\n')
    reversed_lines = []
    for line in lines:
        if line.startswith('---') or line.startswith('+++'):
            reversed_lines.append(line)
        elif line.startswith('-') and not line.startswith('---'):
            reversed_lines.append('+' + line[1:])
        elif line.startswith('+') and not line.startswith('+++'):
            reversed_lines.append('-' + line[1:])
        else:
            reversed_lines.append(line)
    return '\n'.join(reversed_lines)


def parse_changed_locations(bug_patch):
    """Extract files and lines changed in the patch

    Args:
        bug_patch: The patch string

    Returns:
        dict with 'files' (set of filenames) and 'lines' (dict of filename -> set of line numbers)
    """
    changed_files = set()
    changed_lines = {}

    current_file = None
    for line in bug_patch.split('\n'):
        # Extract filename from +++ line
        if line.startswith('+++'):
            match = re.search(r'\+\+\+ b/(.+)', line)
            if match:
                current_file = match.group(1)
                changed_files.add(current_file)
                changed_lines[current_file] = set()

        # Extract line numbers from @@ hunk headers
        elif line.startswith('@@') and current_file:
            match = re.search(r'@@ -\d+,?\d* \+(\d+),?(\d*)', line)
            if match:
                start = int(match.group(1))
                count = int(match.group(2)) if match.group(2) else 1
                changed_lines[current_file].update(range(start, start + count))

    return {'files': changed_files, 'lines': changed_lines}


def parse_flagged_locations(report):
    """Extract files and lines flagged in the report

    Args:
        report: The markdown report from the code review system

    Returns:
        dict with 'files' (set of filenames) and 'lines' (dict of filename -> set of line numbers)
    """
    flagged_files = set()
    flagged_lines = {}

    # Parse markdown table from report
    in_table = False
    for line in report.split('\n'):
        if '| Issue | File | Lines |' in line:
            in_table = True
            continue
        if in_table and line.strip().startswith('|') and not line.strip().startswith('|---'):
            parts = [p.strip() for p in line.split('|')]
            if len(parts) > 3:
                file_path = parts[2]
                lines_str = parts[3]

                if file_path and file_path != 'File':
                    flagged_files.add(file_path)
                    if file_path not in flagged_lines:
                        flagged_lines[file_path] = set()

                    # Strip brackets like [82-85] -> 82-85
                    lines_str = lines_str.strip('[]')

                    # Parse line numbers (e.g., "7-10", "24-25", "9")
                    for line_range in lines_str.split(','):
                        line_range = line_range.strip()
                        if '-' in line_range:
                            start, end = map(int, line_range.split('-'))
                            flagged_lines[file_path].update(range(start, end + 1))
                        elif line_range.isdigit():
                            flagged_lines[file_path].add(int(line_range))

    return {'files': flagged_files, 'lines': flagged_lines}


def calculate_location_metrics(actual, flagged):
    """Calculate location-based overlap metrics with 5-line tolerance

    Recall: Of all actual changed lines, how many did we flag (within 5 line tolerance)?
    Precision: Of all flagged lines, how many correspond to actual changes (within 5 line tolerance)?

    Args:
        actual: dict from parse_changed_locations
        flagged: dict from parse_flagged_locations

    Returns:
        dict with 'file_recall', 'line_recall', 'line_precision'
    """
    # File-level recall
    file_recall = len(flagged['files'] & actual['files']) / len(actual['files']) if actual['files'] else 0.0

    # Line-level metrics
    total_actual_lines = 0
    total_flagged_lines = 0
    actual_lines_matched = 0  # For recall: how many actual lines have a nearby flagged line
    flagged_lines_matched = 0  # For precision: how many flagged lines have a nearby actual line

    for file in actual['files']:
        actual_lines = actual['lines'].get(file, set())
        flagged_lines_in_file = flagged['lines'].get(file, set())

        total_actual_lines += len(actual_lines)
        total_flagged_lines += len(flagged_lines_in_file)

        # Count actual lines that have at least one flagged line within 5 lines (for recall)
        for actual_line in actual_lines:
            if any(abs(actual_line - flagged_line) <= 5 for flagged_line in flagged_lines_in_file):
                actual_lines_matched += 1

        # Count flagged lines that have at least one actual line within 5 lines (for precision)
        for flagged_line in flagged_lines_in_file:
            if any(abs(flagged_line - actual_line) <= 5 for actual_line in actual_lines):
                flagged_lines_matched += 1

    line_recall = actual_lines_matched / total_actual_lines if total_actual_lines > 0 else 0.0
    line_precision = flagged_lines_matched / total_flagged_lines if total_flagged_lines > 0 else 0.0

    return {
        'file_recall': file_recall,
        'line_recall': line_recall,
        'line_precision': line_precision
    }
