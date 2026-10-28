"""Deterministic public-only data. This is not a scanner/image receipt."""
from ci_protocol import canonical,sha
REPORT=canonical({'schema':'generic.synthetic-receipt.v1','status':'passed'})
BLOB=b'Public disposable synthetic payload.\n'
REPORT_SHA=sha(REPORT)
BLOB_SHA=sha(BLOB)
CLOSURE_SHA=sha(canonical({'report':REPORT_SHA,'blob':BLOB_SHA}))

def consume(read_input,emit):
    report=read_input('/input/privacy.json',4096)
    blob=read_input('/input/oci/synthetic.bin',4096)
    from ci_protocol import closed,decode,require
    require(sha(report)==REPORT_SHA and sha(blob)==BLOB_SHA,'fixture.input_changed')
    require(closed(decode(report),{'schema','status'})==
            {'schema':'generic.synthetic-receipt.v1','status':'passed'},'fixture.report_semantics')
    emit(canonical({'status':'passed','privacyReceiptSha256':REPORT_SHA,'ociClosureSha256':CLOSURE_SHA}))
    return 0
