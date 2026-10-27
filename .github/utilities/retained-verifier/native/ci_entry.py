"""Disarmed outer guest entry: result custody/serial precede normal poweroff."""
from pathlib import Path
import sys
import ci_adapter
import ci_metadata
import ci_native_port
from ci_protocol import Refusal,canonical,require,sha,write_once
_BOUND_CONTEXT=None


class Entry:
    def __init__(self,port,custody_directory,result_directory,*,clock,emit):
        self.port=port;self.driver=ci_adapter.Adapter(port,custody_directory,clock=clock)
        self.directory=Path(result_directory);self.directory.mkdir(mode=0o700)
        self.emit=emit;self.used=False
    def run(self,raw):
        require(not self.used,'ci.entry_once');self.used=True
        result=None;saved=False;emitted=False
        try:
            result=self.driver.run(raw)
            payload=canonical(result);require(len(payload)<=16384,'ci.entry_result_cap')
            write_once(self.directory/'unit-result.json',payload);saved=True
            self.emit(payload+b'\n');emitted=True
        finally:
            # Even custody/emitter failure cannot skip the exact requested
            # normal poweroff. No retry and no fabricated outer exit proof.
            if 'shutdown' not in self.port.effect_intents:self.port.normal_guest_shutdown()
            shutdown=self.port.poweroff_after_result_custody()
        return {'unitResult':result,'unitResultSaved':saved,'serialEmitted':emitted,'shutdown':shutdown,
                'outerExitVerified':False}


def run_bound_native(context):
    # The future approved public build must supply this source-bound context
    # after manifest/role verification. No dictionary or CLI field issues it.
    require(_BOUND_CONTEXT is not None and context is _BOUND_CONTEXT,'ci.entry_capability_unissued')
    ops=ci_native_port.NativeOps(context.ops_capability)
    admission=ci_metadata.Admission(ops,context.apt_paths,context.keyring_sha256,context.clock)
    port=ci_native_port.Port(ops,context.runtime_manifest,session_root=context.session_root,
                            clock=context.clock,metadata_admission=admission)
    entry=Entry(port,context.custody_directory,context.result_directory,clock=context.clock,
                emit=lambda raw:sys.stdout.buffer.write(raw) and sys.stdout.buffer.flush())
    return entry.run(context.context_raw)


def main():return run_bound_native(_BOUND_CONTEXT)


if __name__=='__main__':main()
