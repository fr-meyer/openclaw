"""Host-owned persistent accounting for one future approved Docker task.

Import is inert. Only the hosted owner may call create/kill/release. Tests use
temporary regular files and injected command callbacks, never host cgroups.
An active systemd slice retains raw hierarchical counters after its Docker
scope disappears; unit cache values and missing paths never grant proof.
"""
import json
import os
from pathlib import Path
import platform
import re
import stat
import time


class Refusal(ValueError):
    pass


class ObservationFailure(Refusal):
    def __init__(self, operation, cause):
        self.operation, self.cause = operation, cause
        super().__init__(operation + ": " + str(cause))


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def fields(data):
    require(isinstance(data, bytes) and len(data) < 4096, "unbounded cgroup observation")
    rows = [line.split() for line in data.decode("ascii").splitlines()]
    require(all(len(row) == 2 for row in rows)
            and len({row[0] for row in rows}) == len(rows), "malformed cgroup observation")
    return dict(rows)


UNIT_FIELDS = ("Id", "LoadState", "ActiveState", "SubState", "Transient", "Description",
               "InvocationID", "ControlGroup", "StopWhenUnneeded", "CollectMode",
               "CPUAccounting", "MemoryAccounting", "TasksAccounting", "DropInPaths")
NAME = re.compile(r"v98proof[0-9]+m[123]\.slice\Z")
INVOCATION = re.compile(r"[0-9a-f]{32}\Z")


class SliceOwner:
    def __init__(self, command, name, cgroup_root=Path("/sys/fs/cgroup"), *,
                 clock=time.monotonic, pause=time.sleep):
        require(isinstance(name, str) and NAME.fullmatch(name) and len(name) <= 96,
                "task slice name is not exact")
        self.command, self.name = command, name
        self.root = Path(cgroup_root)
        self.path = self.root / name
        self.clock, self.pause = clock, pause
        self.description = "OpenClaw v98 owned accounting " + name
        self.root_fd = self.fd = None
        self.root_identity = None
        self.identity = self.invocation_id = None
        self.expected_child = None
        self.child_identity = None
        self.baseline = None
        self.last_cpu = None
        self.final = None
        self.creation_attempted = self.created = self.released = False
        self.systemd_version = None
        self.kernel = platform.release()

    def _command(self, argv):
        data = self.command(argv, timeout=5, stdout_limit=32768)
        require(isinstance(data, bytes) and len(data) < 32768, "unbounded owner command result")
        return data

    @property
    def directory_fd(self):
        return self.fd

    def _show(self):
        data = self._command(["systemctl", "show", "--no-pager",
                              *["--property=" + key for key in UNIT_FIELDS], self.name])
        rows = data.decode("utf-8").splitlines()
        require(all("=" in row for row in rows), "malformed systemd unit observation")
        pairs = [row.split("=", 1) for row in rows]
        require(len({row[0] for row in pairs}) == len(pairs), "duplicate systemd unit observation")
        result = dict(pairs)
        require(set(result) == set(UNIT_FIELDS), "systemd owner fields missing or unexpected")
        return result

    def _unit_identity(self, unit, *, active=True):
        require(unit["Id"] == self.name and unit["LoadState"] == "loaded"
                and unit["Transient"] == "yes" and unit["Description"] == self.description
                and unit["StopWhenUnneeded"] == "no" and unit["CollectMode"] == "inactive"
                and all(unit[key] == "yes" for key in
                        ("CPUAccounting", "MemoryAccounting", "TasksAccounting"))
                and unit["DropInPaths"] == "", "task slice ownership or retention changed")
        require(INVOCATION.fullmatch(unit["InvocationID"])
                and unit["InvocationID"] != "0" * 32, "task slice invocation absent")
        if self.invocation_id is not None:
            require(unit["InvocationID"] == self.invocation_id, "task slice invocation changed")
        if active:
            require(unit["ActiveState"] == "active" and unit["SubState"] == "active"
                    and unit["ControlGroup"] == "/" + self.name,
                    "task slice is not the original active parent")
        else:
            require(unit["ControlGroup"] in ("", "/" + self.name),
                    "stopped task slice cgroup ownership changed")
        return unit

    def _check_parent(self):
        require(self.created and not self.released and self.fd is not None,
                "task accounting parent is not bound")
        held = os.fstat(self.fd)
        held_root = os.fstat(self.root_fd)
        current_root = os.stat(self.root, follow_symlinks=False)
        current = os.stat(self.name, dir_fd=self.root_fd, follow_symlinks=False)
        require(stat.S_ISDIR(held_root.st_mode) and stat.S_ISDIR(current_root.st_mode)
                and (held_root.st_dev, held_root.st_ino) == self.root_identity
                and (current_root.st_dev, current_root.st_ino) == self.root_identity,
                "task cgroup root was removed or replaced")
        require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(current.st_mode)
                and (held.st_dev, held.st_ino) == self.identity
                and (current.st_dev, current.st_ino) == self.identity,
                "task accounting parent was removed or replaced")

    def _read(self, name):
        self._check_parent()
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except OSError as issue:
            raise ObservationFailure("parent " + name + " open", issue) from issue
        try:
            try:
                data = os.read(fd, 4096)
            except OSError as issue:
                raise ObservationFailure("parent " + name + " read", issue) from issue
        finally:
            os.close(fd)
        require(len(data) < 4096, "unbounded task parent observation")
        self._check_parent()
        return data

    def _inventory(self, *, no_children=False):
        require(not self._read("cgroup.procs").strip(), "unexpected direct task parent process")
        entries = os.listdir(self.fd)
        require(len(entries) <= 256 and sum(len(name.encode()) for name in entries) <= 16384,
                "task parent namespace unbounded")
        for name in entries:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            require(not stat.S_ISLNK(info.st_mode), "task parent namespace alias")
            if stat.S_ISDIR(info.st_mode):
                require(not no_children and name == self.expected_child,
                        "unexpected task parent child")
                if self.child_identity is not None:
                    require((info.st_dev, info.st_ino) == self.child_identity,
                            "task container child was replaced")
        self._check_parent()

    def _bus_result(self, method, signature, arguments):
        data = self._command(["busctl", "--system", "--no-pager", "--json=short", "call",
                              "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager", method, signature, *arguments])
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, "duplicate manager result key")
                result[key] = value
            return result
        result = json.loads(data, object_pairs_hook=unique)
        require(isinstance(result, dict) and set(result) == {"type", "data"},
                "manager result is not typed data")
        return result

    def _bus(self, method, signature, arguments):
        result = self._bus_result(method, signature, arguments)
        require(isinstance(result, dict) and result.get("type") == "o"
                and isinstance(result.get("data"), list) and len(result["data"]) == 1
                and isinstance(result["data"][0], str)
                and re.fullmatch(r"/org/freedesktop/systemd1/job/[0-9]+", result["data"][0]),
                "systemd returned no exact task job")
        return result["data"][0]

    def _listed_unit(self):
        # Unlike systemctl show, this typed manager query does not load an
        # absent unit and returns a successful empty array after transient GC.
        # A command failure is never interpreted as NoSuchUnit.
        result = self._bus_result("ListUnitsByPatterns", "asas", ["0", "1", self.name])
        require(result["type"] == "a(ssssssouso)" and isinstance(result["data"], list)
                and len(result["data"]) == 1 and isinstance(result["data"][0], list)
                and len(result["data"][0]) <= 1, "task unit listing malformed or ambiguous")
        rows = result["data"][0]
        if not rows:
            return None
        row = rows[0]
        require(isinstance(row, list) and len(row) == 10
                and all(isinstance(row[index], str) for index in (0, 1, 2, 3, 4, 5, 6, 8, 9))
                and type(row[7]) is int and row[0] == self.name and row[1] == self.description,
                "task unit listing ownership changed")
        return row

    def create(self):
        require(not self.creation_attempted, "task accounting creation already attempted")
        version = self._command(["systemctl", "--version"]).decode("utf-8")
        require(re.match(r"systemd 255(?:\s|\.)", version), "unreviewed systemd major version")
        self.systemd_version = version.splitlines()[0][:512]
        try:
            os.stat(self.path, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refusal("task accounting parent path already exists")
        properties = [("Description", "s", self.description), ("StopWhenUnneeded", "b", "false"),
                      ("CollectMode", "s", "inactive"), ("CPUAccounting", "b", "true"),
                      ("MemoryAccounting", "b", "true"), ("TasksAccounting", "b", "true"),
                      ("CPUQuotaPerSecUSec", "t", "1000000"),
                      ("CPUQuotaPeriodUSec", "t", "100000"),
                      ("MemoryMax", "t", str(1024 ** 3)), ("MemorySwapMax", "t", "0"),
                      ("TasksMax", "t", "128")]
        arguments = [self.name, "fail", str(len(properties))]
        for name, kind, value in properties:
            arguments.extend([name, kind, value])
        arguments.append("0")  # no auxiliary units
        self.creation_attempted = True
        # StartTransientUnit atomically rejects an already loaded/non-pristine
        # unit. Never replace/adopt a pre-existing slice or unit file.
        job = self._bus("StartTransientUnit", "ssa(sv)a(sa(sv))", arguments)
        until = self.clock() + 5
        while True:
            unit = self._show()
            if unit["ActiveState"] == "active":
                self._unit_identity(unit)
                break
            require(unit["LoadState"] == "loaded" and unit["Transient"] == "yes"
                    and unit["Description"] == self.description
                    and unit["ActiveState"] in ("inactive", "activating"),
                    "task slice failed to activate")
            require(self.clock() < until, "task slice activation timed out")
            self.pause(0.05)
        self.invocation_id = unit["InvocationID"]
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_info = os.fstat(self.root_fd)
        self.root_identity = (root_info.st_dev, root_info.st_ino)
        try:
            self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=self.root_fd)
            info = os.fstat(self.fd)
            require(info.st_uid == os.geteuid(), "task accounting parent is not caller-owned")
            self.identity = (info.st_dev, info.st_ino)
            self.created = True
            self._check_parent()
            require(self._read("cgroup.type").strip() == b"domain", "task parent is not domain cgroup")
            quota = self._read("cpu.max").decode("ascii").split()
            require(len(quota) == 2 and all(value.isdecimal() for value in quota)
                    and int(quota[0]) == int(quota[1]) and int(quota[1]) > 0,
                    "task parent is not limited to one CPU")
            for file, expected in (("memory.max", str(1024 ** 3)), ("memory.swap.max", "0"),
                                   ("pids.max", "128")):
                require(self._read(file).decode("ascii").strip() == expected,
                        "task parent resource limit changed: " + file)
            self._inventory(no_children=True)
            require(not self.populated(), "new task parent is populated")
            self.baseline = self.cpu_total()
            require(self.baseline == 0, "new task parent has prior CPU usage")
            self._unit_identity(self._show())
        except Exception:
            # Descriptor close is allowed; stopping an uncertain unit is not.
            self.close()
            raise
        return {**self.receipt(), "startJob": job}

    def expect_container(self, container_id):
        require(self.created and self.expected_child is None
                and self.final is None and self.baseline == 0 and self.cpu_total() == 0
                and isinstance(container_id, str) and re.fullmatch(r"[0-9a-f]{64}", container_id),
                "task container identity invalid or already assigned")
        self._inventory(no_children=True)
        self.expected_child = "docker-" + container_id + ".scope"
        self._inventory()

    def bind_child(self, cgroup, identity, pid=None):
        require(self.expected_child is not None, "task container identity was never assigned")
        cgroup = Path(cgroup)
        require(cgroup == self.path / self.expected_child, "container is outside exact task parent")
        self._unit_identity(self._show())
        self._inventory()
        fd = os.open(self.expected_child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            require((info.st_dev, info.st_ino) == tuple(identity), "container child identity changed")
            require(self.child_identity is None or self.child_identity == tuple(identity),
                    "container child binding changed")
            if pid is not None:
                require(type(pid) is int and pid > 1, "container child PID invalid")
                processes = os.open("cgroup.procs", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    data = os.read(processes, 4096)
                finally:
                    os.close(processes)
                require(len(data) < 4096 and str(pid) in data.decode("ascii").split(),
                        "container PID absent from exact task child")
            self._check_parent()
            current = os.stat(self.expected_child, dir_fd=self.fd, follow_symlinks=False)
            require(stat.S_ISDIR(current.st_mode)
                    and (current.st_dev, current.st_ino) == tuple(identity),
                    "container child changed during binding")
            self.child_identity = tuple(identity)
        finally:
            os.close(fd)
        return self.receipt()

    def cpu_total(self):
        data = fields(self._read("cpu.stat"))
        value = data.get("usage_usec", "")
        require(value.isdecimal(), "task parent CPU usage missing")
        value = int(value)
        require(self.last_cpu is None or value >= self.last_cpu, "task parent CPU usage decreased")
        self.last_cpu = value
        return value

    def cpu_delta(self):
        require(self.baseline == 0, "pre-start task baseline was never captured")
        return self.cpu_total() - self.baseline

    def populated(self):
        value = fields(self._read("cgroup.events")).get("populated")
        require(value in ("0", "1"), "task parent population observation missing")
        return value == "1"

    def kill(self):
        self._unit_identity(self._show())
        self._inventory()
        if not self.populated():
            return None
        require(self.child_identity is not None, "populated task child was never bound")
        try:
            fd = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except OSError as issue:
            raise ObservationFailure("parent cgroup.kill open", issue) from issue
        try:
            # Revalidate namespace and original parent after obtaining the
            # mutation descriptor; replacement must refuse before any write.
            self._unit_identity(self._show())
            self._inventory()
            try:
                require(os.write(fd, b"1\n") == 2, "short task parent kill write")
            except OSError as issue:
                raise ObservationFailure("parent cgroup.kill write", issue) from issue
        finally:
            os.close(fd)
        signalled = self.clock()
        until = signalled + 5
        while self.populated():
            require(self.clock() < until, "task parent extinction was not observed")
            self.pause(0.05)
        self._unit_identity(self._show())
        self._inventory()
        return signalled

    def final_observation(self, last_cpu):
        self.final = None
        require(type(last_cpu) is int and last_cpu >= 0, "last task CPU observation invalid")
        self._unit_identity(self._show())
        self._inventory()
        require(not self.populated(), "task parent remains populated before final CPU")
        cpu = self.cpu_delta()
        require(cpu >= last_cpu, "final task CPU observation decreased")
        require(not self.populated(), "task parent repopulated during final CPU")
        require(self.cpu_delta() == cpu, "task parent final CPU observation unstable")
        require(not self.populated(), "task parent repopulated after final CPU")
        self._unit_identity(self._show())
        self._inventory()
        self.final = {**self.receipt(), "aggregateCpuUsec": cpu,
                      "totalCpuUsec": self.last_cpu, "baselineCpuUsec": self.baseline,
                      "cgroupDevInode": self.identity, "populated": False,
                      "extinctionObserved": True, "finalCpuVerified": True}
        return dict(self.final)

    def release(self):
        """Caller must first retain evidence and remove exact stopped Docker ID."""
        require(self.final is not None, "task parent has no retained final observation")
        self._unit_identity(self._show())
        self._inventory(no_children=True)
        require(not self.populated() and self.cpu_delta() == self.final["aggregateCpuUsec"],
                "task parent changed after final observation")
        self._unit_identity(self._show())
        self._inventory(no_children=True)
        require(not self.populated(), "task parent repopulated before release")
        job = self._bus("StopUnit", "ss", [self.name, "fail"])
        until = self.clock() + 5
        while True:
            listed = self._listed_unit()
            unit = None
            if listed is not None:
                unit = self._show()
                self._unit_identity(unit, active=False)
                require(unit["ActiveState"] in ("inactive", "deactivating"),
                        "task slice did not stop")
            try:
                current = os.stat(self.name, dir_fd=self.root_fd, follow_symlinks=False)
            except FileNotFoundError:
                require(listed is None or unit["ActiveState"] == "inactive",
                        "task path vanished before unit stopped")
                break
            require((current.st_dev, current.st_ino) == self.identity,
                    "task parent replaced during release")
            require(self.clock() < until, "task parent release timed out")
            self.pause(0.05)
        self.released = True
        self.close()
        return {"unit": self.name, "invocationId": self.invocation_id,
                "stopJob": job, "released": True,
                "extinctionAuthority": "PRIOR_POSITIVE_BOUND_PARENT_POPULATED_ZERO"}

    def receipt(self):
        return {"unit": self.name, "description": self.description,
                "invocationId": self.invocation_id, "controlGroup": "/" + self.name,
                "parentDevInode": self.identity, "expectedChild": self.expected_child,
                "childDevInode": self.child_identity,
                "preStartCpuBaseline": self.baseline, "systemdVersion": self.systemd_version,
                "kernelRelease": self.kernel, "creationAttempted": self.creation_attempted,
                "created": self.created, "released": self.released, "keeperProcess": False}

    def close(self):
        """Close held descriptors only; never stop or remove an uncertain unit."""
        for key in ("fd", "root_fd"):
            fd = getattr(self, key)
            if fd is not None:
                setattr(self, key, None)
                os.close(fd)
