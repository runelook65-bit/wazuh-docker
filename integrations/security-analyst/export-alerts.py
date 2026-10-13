"""Prepare a bounded local Wazuh JSONL file for Security Analyst; no network access."""
import argparse
from collections import deque
import json
from pathlib import Path
import sys

MAX_BYTES = 10 * 1024 * 1024
MAX_LINE = 200000


def export(path, limit):
    rows = deque()
    size = total = 0
    with Path(path).open('rb') as handle:
        while True:
            line = handle.readline(MAX_LINE + 1)
            if not line:
                break
            total += 1
            if len(line) > MAX_LINE:
                raise ValueError(f'Line {total} exceeds 200 KB. Select a smaller source record.')
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError) as error:
                raise ValueError(f'Line {total} is not valid UTF-8 JSON.') from error
            if not isinstance(row, dict) or not isinstance(row.get('agent'), dict) or not (isinstance(row.get('rule'), dict) or isinstance(row.get('data'), dict)):
                raise ValueError(f'Line {total} is not a Wazuh alert.')
            encoded = (json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
            if len(rows) == limit:
                size -= len(rows.popleft())
            rows.append(encoded)
            size += len(encoded)
            if size > MAX_BYTES:
                raise ValueError('Output exceeds 10 MB. Repeat with a smaller --limit.')
    return b''.join(rows), total, len(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Local alerts.json / JSONL path; contains sensitive raw records')
    parser.add_argument('--limit', type=int, default=10000, help='Number of last file records (1–10000); file order is retained')
    args = parser.parse_args()
    if not 1 <= args.limit <= 10000:
        parser.error('--limit must be 1–10000')
    try:
        payload, total, kept = export(args.input, args.limit)
    except (OSError, ValueError) as error:
        print(f'Export refused: {error}', file=sys.stderr)
        sys.exit(1)
    print(f'{kept} of {total} source lines exported ({len(payload)} bytes). {total-kept} earlier lines excluded. No records were uploaded.', file=sys.stderr)
    sys.stdout.buffer.write(payload)
