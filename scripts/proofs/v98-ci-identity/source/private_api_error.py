"""Bounded private API diagnostics. No I/O, headers, credentials or raw hashes."""
import json
import re


API_ERROR_CAP = 4096
API_ERROR_WIRE_CAP = 65536


def _redact_api_error_text(value, current_token, limit):
    if not isinstance(value, str):
        return None, False, False
    if len(value) > API_ERROR_WIRE_CAP or len(value.encode('utf-8', 'replace')) > API_ERROR_WIRE_CAP:
        return '[OVERSIZE_TEXT_OMITTED]', False, True
    text = value
    if isinstance(current_token, str) and current_token:
        text = text.replace(current_token, '[REDACTED]')
    patterns = (
        r'(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
        r'(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie|x-goog-api-key|x-api-key)\s*:\s*[^\r\n]*',
        r'(?i)\bbearer\s+[^\s,;\"\']+',
        r'\bya29\.[A-Za-z0-9._~\-]+',
        r'\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}',
        r'(?i)\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|private[_-]?key)\b[\"\']?\s*[:=]\s*[\"\']?[^\s\"\'&,;}]+',
        r'(?i)https?://[^\s/@]+:[^\s/@]+@',
    )
    for pattern in patterns:
        text = re.sub(pattern, '[REDACTED]', text)
    redacted = text != value
    text = re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', ' ', text)
    text = ' '.join(text.split())
    raw = text.encode('utf-8', 'replace')
    truncated = len(raw) > limit
    return raw[:limit].decode('utf-8', 'ignore'), redacted, truncated


def _private_api_error_diagnostic(value, current_token):
    """Project error.message, BadRequest and safe ErrorInfo into <=4096 bytes."""
    out = {'captureStatus': 'PROJECTED_REDACTED_ERROR', 'privateOnly': True,
           'redactionsApplied': False, 'truncated': False,
           'fieldViolations': [], 'errorInfo': []}
    error = value.get('error') if isinstance(value, dict) else None
    if not isinstance(error, dict):
        out['captureStatus'] = 'UNSTRUCTURED_ERROR_BODY_OMITTED'
        return out

    def clean(value, limit):
        text, redacted, truncated = _redact_api_error_text(value, current_token, limit)
        out['redactionsApplied'] = out['redactionsApplied'] or redacted
        out['truncated'] = out['truncated'] or truncated
        return text

    def size(value):
        return len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())

    code = error.get('code')
    if type(code) is int and 0 <= code <= 599:
        out['code'] = code
    status = error.get('status')
    if status in ('OK', 'CANCELLED', 'UNKNOWN', 'INVALID_ARGUMENT', 'DEADLINE_EXCEEDED',
                  'NOT_FOUND', 'ALREADY_EXISTS', 'PERMISSION_DENIED', 'RESOURCE_EXHAUSTED',
                  'FAILED_PRECONDITION', 'ABORTED', 'OUT_OF_RANGE', 'UNIMPLEMENTED',
                  'INTERNAL', 'UNAVAILABLE', 'DATA_LOSS', 'UNAUTHENTICATED'):
        out['status'] = status
    message = clean(error.get('message'), 1024)
    if message is not None:
        out['message'] = message
    details = error.get('details', [])
    if not isinstance(details, list):
        details = []
        out['truncated'] = True
    if len(details) > 8:
        out['truncated'] = True
    violations, infos = [], []
    for detail in details[:8]:
        if not isinstance(detail, dict):
            continue
        if detail.get('@type') == 'type.googleapis.com/google.rpc.BadRequest':
            items = detail.get('fieldViolations', [])
            if not isinstance(items, list):
                out['truncated'] = True
                continue
            if len(items) > 4:
                out['truncated'] = True
            for item in items[:4]:
                if not isinstance(item, dict):
                    continue
                row = {}
                for key, cap in (('field', 128), ('description', 384)):
                    text = clean(item.get(key), cap)
                    if text is not None:
                        row[key] = text
                if row:
                    violations.append(row)
        elif detail.get('@type') == 'type.googleapis.com/google.rpc.ErrorInfo':
            row = {}
            for key in ('reason', 'domain'):
                text = clean(detail.get(key), 128)
                if text is not None:
                    row[key] = text
            metadata = detail.get('metadata', {})
            selected = {}
            if isinstance(metadata, dict):
                for key in ('service', 'consumer', 'permission', 'method', 'resource', 'constraint'):
                    text = clean(metadata.get(key), 96)
                    if text is not None:
                        selected[key] = text
            if row or selected:
                infos.append((row, selected))
    if len(violations) > 4 or len(infos) > 2:
        out['truncated'] = True
    for row in violations[:4]:
        out['fieldViolations'].append(row)
        if size(out) > API_ERROR_CAP:
            out['fieldViolations'].pop()
            out['truncated'] = True
    for row, metadata in infos[:2]:
        out['errorInfo'].append(row)
        if size(out) > API_ERROR_CAP:
            out['errorInfo'].pop()
            out['truncated'] = True
            continue
        if metadata:
            row['metadata'] = {}
            for key, text in metadata.items():
                row['metadata'][key] = text
                if size(out) > API_ERROR_CAP:
                    del row['metadata'][key]
                    out['truncated'] = True
    assert size(out) <= API_ERROR_CAP
    return out
