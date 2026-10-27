"""Inert unit properties generated from the exact reviewed design profile."""
from pathlib import Path
from ci_protocol import canonical, decode, identity, require, sha

DESIGN_PROFILE_SHA = "0e428b6ca56752ba7f03b6dc201169c47fa7990e085781eca78b65de7fbe53c5"
ARMED = False


def properties(profile_bytes, session, session_root):
    require(sha(profile_bytes) == DESIGN_PROFILE_SHA, "design_profile_changed")
    doc = decode(profile_bytes, 16384)
    name, _ = identity(session)
    root = str(Path(session_root))
    require(Path(root).is_absolute() and Path(root).as_posix() == root and
            all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-." for c in root),
            "profile_root_path")
    require(".." not in Path(root).parts, "profile_root_path")
    result = []
    for value in doc["properties"]:
        value = value.replace("<root0700-host-parent/session/root>", root + "/root")
        value = value.replace("<root-private-evidence>", root + "/evidence")
        value = value.replace("<fresh-ocv-session-name>", name)
        value = value.replace("<same-fresh-dynamic-group>", name)
        value = value.replace("<pinned-static-env-entry>", "/code/static-entry")
        value = value.replace("<exact-fresh-dynamic-identity-name>", name)
        require("<" not in value and ">" not in value and "\x00" not in value and "\n" not in value,
                "profile_placeholder")
        result.append(value)
    # This does not submit a unit or create any identity. Backend is separately held.
    return tuple(result)


if __name__ == "__main__":
    raise SystemExit("disarmed_local_source_only")
