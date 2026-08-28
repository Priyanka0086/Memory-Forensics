#!/usr/bin/env python3
"""
unified_pipeline.py

Unified pipeline: memory_pipeline.py + threat_intel_pipeline.py combined
into a single module. No logic from either original script was changed --
only combined into one file, each kept as its own independent set of
stages, wired together under one CLI / one main().

  STAGE 1  merge            (from merge_memory_artifacts.py)
  STAGE 2  extract features (from extract_features.py)
  STAGE 3  baseline compare (PRE vs DURING)
  STAGE 4  anomaly scoring  (PRE vs DURING, z-score)
  STAGE 5  evidence builder (PRE and DURING)
  STAGE 6  threat intel     (from threat_intel_pipeline.py -- PCAP/Sysmon
                              IoC extraction, filtering, and enrichment via
                              VirusTotal + MalwareBazaar)

Stages 1-5 are the original memory_pipeline.py, entirely unchanged.
Stage 6 is the original threat_intel_pipeline.py, entirely unchanged
(extraction, filtering, and enrichment functions are copied verbatim),
just re-parented under the same argparse/main() so both pipelines run
from one command instead of two separate scripts. Stage 6 is independent
of stages 1-5 (it does not consume their output) -- it runs off its own
--pcap/--sysmon inputs, exactly like the standalone script did.

USAGE (VSCode / terminal)
--------------------------
    # memory forensics only (same as before)
    python unified_pipeline.py --pre-input-folder /path/to/dataset_pre \
        --during-input-folder /path/to/dataset_during

    # threat intel only (same as before)
    python unified_pipeline.py --skip-pre --skip-during \
        --skip-baseline-compare --skip-scoring --skip-evidence \
        --pcap capture.pcap --sysmon sysmon.csv

    # both in one run
    python unified_pipeline.py --pre-input-folder /path/to/dataset_pre \
        --during-input-folder /path/to/dataset_during \
        --pcap capture.pcap --sysmon sysmon.csv

    # optional reference lists for the feature stage
    python unified_pipeline.py --pre-input-folder /path/to/dataset_pre \
        --during-input-folder /path/to/dataset_during \
        --known-malware-mutex known_mutex.txt \
        --known-dll-baseline known_dlls.txt

If you omit the CLI flags entirely, the memory-forensics side falls back to
the same hardcoded paths that were in the original two scripts (see
DEFAULT_* below); the threat-intel side simply does not run unless --pcap
and/or --sysmon is supplied (same "optional" behavior it had standalone).
"""

import argparse
import csv
import ipaddress
import json
import math
import re
import sys
import os
import time
import requests
import pandas as pd
from scapy.all import rdpcap, DNSQR, IP
from collections import Counter, defaultdict
from pathlib import Path

# =============================================================================
# =========================  STAGE 1: MERGE  =================================
# (from merge_memory_artifacts.py -- logic unchanged)
# =============================================================================

# ---------------- CONFIG ---------------- #

PID_KEY_CANDIDATES = [
    "pid", "Pid", "PID", "ProcessId", "process_id", "Process_Id",
    "EPROCESS_Pid", "process_pid", "Owner_Pid", "OwnerPid",
]

PPID_KEY_CANDIDATES = [
    "ppid", "Ppid", "PPID", "ParentPid", "parent_pid", "Parent_Pid",
]

MULTI_RECORD_CATEGORIES = {
    "mutex", "vad", "threads", "handles", "dlls",
    "netstat", "drivers", "impersonation",
}

SINGLE_RECORD_CATEGORIES = {"pslist", "procinfo"}

ALL_CATEGORIES = MULTI_RECORD_CATEGORIES | SINGLE_RECORD_CATEGORIES

# Map Velociraptor filenames -> category
ARTIFACT_MAP = {
    "Windows.System.Pslist": "pslist",
    "Windows.Network.Netstat": "netstat",
    "Windows.System.Threads": "threads",
    "Windows.System.Handle": "handles",
    "Windows.System.DLL": "dlls",
    "Windows.System.Drivers": "drivers",
    "Windows.Memory.ProcessInfo": "procinfo",
    "Windows.Memory.VAD": "vad",
    "Windows.Detection.Mutant": "mutex",
    "Windows.Detection.Impersonation": "impersonation",
}

# ---------------- FILE LOADER ---------------- #

def sniff_and_load(path: str):
    p = Path(path)
    raw = p.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not raw:
        return []

    if raw.startswith("["):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
        except:
            pass

    if raw.startswith("{"):
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if len(lines) == 1:
            try:
                obj = json.loads(raw)
                return [obj]
            except:
                pass

        records = []
        for line in lines:
            try:
                records.append(json.loads(line.strip().rstrip(",")))
            except:
                return []
        return records

    try:
        with p.open(newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    except:
        return []

# ---------------- HELPERS ---------------- #

def extract_key(record, candidates):
    for key in candidates:
        if key in record and record[key] not in (None, "", "-"):
            try:
                return str(int(str(record[key]).strip()))
            except:
                return str(record[key]).strip()
    return None

# ---------------- AUTO DISCOVERY ---------------- #

def discover_files(input_folder):
    category_files = {cat: [] for cat in ALL_CATEGORIES}

    for root, dirs, files in os.walk(input_folder):
        for file in files:
            for artifact_name, category in ARTIFACT_MAP.items():
                if artifact_name in file and file.endswith(".json"):
                    full_path = os.path.join(root, file)
                    category_files[category].append(full_path)

    print("\n[+] Artifact Discovery Summary:")
    for cat, files in category_files.items():
        print(f"    {cat}: {len(files)} file(s)")

    return category_files

# ---------------- MERGE ---------------- #

def merge(category_files, out_path):
    """
    Unchanged merge logic. Additionally RETURNS the merged `result` dict
    (processes + unattributed) so the caller can feed it straight into the
    feature-extraction stage without re-reading the JSON file from disk.
    """
    processes = defaultdict(lambda: {
        "pid": None,
        "ppid": None,
        "pslist": None,
        "procinfo": None,
        "impersonation": [],
        "mutex": [],
        "vad": [],
        "threads": [],
        "handles": [],
        "dlls": [],
        "netstat": [],
        "drivers": [],
    })

    unattributed = defaultdict(list)

    for category, paths in category_files.items():
        for path in paths:
            records = sniff_and_load(path)
            print(f"[+] {category}: {len(records)} records from {path}")

            for rec in records:
                pid = extract_key(rec, PID_KEY_CANDIDATES)

                if pid is None:
                    unattributed[category].append(rec)
                    continue

                proc = processes[pid]
                proc["pid"] = pid

                ppid = extract_key(rec, PPID_KEY_CANDIDATES)
                if ppid and not proc["ppid"]:
                    proc["ppid"] = ppid

                if category in MULTI_RECORD_CATEGORIES:
                    proc[category].append(rec)
                else:
                    proc[category] = rec

    result = {
        "processes": dict(sorted(processes.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)),
        "unattributed": dict(unattributed),
    }

    Path(out_path).write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\n[OK] Merged {len(processes)} processes -> {out_path}")

    return result


# =============================================================================
# =======================  STAGE 2: EXTRACT FEATURES  =========================
# (from extract_features.py -- logic unchanged)
# =============================================================================

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def get_field(record: dict, candidates, default=None):
    """Case-sensitive-first, then case-insensitive lookup across a list of
    candidate key names. Returns `default` if none match or value is empty."""
    if not isinstance(record, dict):
        return default
    for key in candidates:
        if key in record and record[key] not in (None, "", "-"):
            return record[key]
    lower_map = {k.lower(): v for k, v in record.items()}
    for key in candidates:
        v = lower_map.get(key.lower())
        if v not in (None, "", "-"):
            return v
    return default


def as_bool(val, default=None):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "y", "flagged"):
        return True
    if s in ("0", "false", "no", "n"):
        return False
    return default


def as_int(val, default=None):
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return default


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
URL_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)
TEMP_PATH_RE = re.compile(r"\\(temp|tmp|appdata\\local\\temp)\\", re.IGNORECASE)
APPDATA_RE = re.compile(r"\\appdata\\", re.IGNORECASE)


def is_temp_or_appdata(path: str) -> bool:
    if not path:
        return False
    return bool(TEMP_PATH_RE.search(path) or APPDATA_RE.search(path))


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Reference / baseline data (starter lists -- extend or override via CLI)
# ---------------------------------------------------------------------------

DEFAULT_KNOWN_MALWARE_MUTEX_SUBSTRINGS = [
    "MSSE-", "postex_", "_HYDRA_", "Global\\I98B37C7C", "RDPWInst",
    "ASHRSHDU", "Global\\WSAGENT", "AnyDeskMutex",  # examples -- replace with real IOC feed
]

DEFAULT_KNOWN_SYSTEM_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "msvcrt.dll", "sechost.dll", "rpcrt4.dll", "ole32.dll",
    "combase.dll", "ucrtbase.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll",
    "win32u.dll", "gdi32full.dll", "bcrypt.dll", "crypt32.dll", "oleaut32.dll",
}

SUSPICIOUS_PORTS = {4444, 1337, 8080, 9050, 9150}
COMMON_WEB_DNS_PORTS = {80, 443, 53}

EXPECTED_PARENTS = {
    "svchost.exe": {"services.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "explorer.exe": {"userinit.exe"},
}


# ---------------------------------------------------------------------------
# Field-name candidate tables
# ---------------------------------------------------------------------------

F = {
    "mutex_name": ["Name", "MutexName", "mutex_name", "ObjectName"],
    "thread_tid": ["Tid", "ThreadId", "tid"],
    "thread_state": ["State", "ThreadState"],
    "thread_start_addr": ["StartAddress", "Start", "ThreadStartAddress"],
    "thread_module": ["Module", "StartAddressModule", "OwningModule"],
    "thread_suspend_count": ["SuspendCount", "Suspended"],
    "thread_priority": ["Priority", "ThreadPriority"],
    "thread_create_time": ["CreateTime", "StartTime"],
    "thread_exit_time": ["ExitTime"],
    "thread_owning_pid": ["Pid", "OwningPid", "ProcessId"],
    "thread_protection": ["Protection", "MemoryProtection"],

    "handle_type": ["HandleType", "Type"],
    "handle_name": ["HandleName", "Name", "Details"],
    "handle_value": ["HandleValue", "Handle"],
    "handle_granted_access": ["GrantedAccess", "Access"],
    "handle_creator_pid": ["Pid", "ProcessId"],
    "handle_source_pid": ["SourcePid", "CrossPid", "OriginPid"],

    "token_type": ["TokenType", "Type"],
    "token_integrity": ["IntegrityLevel", "Integrity"],
    "token_sid": ["Sid", "TokenSid"],
    "process_sid": ["ProcessSid"],
    "token_user": ["User", "TokenUser"],
    "token_privileges": ["Privileges", "PrivilegeList"],
    "token_source": ["TokenSource", "Source"],
    "token_logon_type": ["LogonType"],
    "token_duplicated": ["Duplicated", "IsDuplicate"],
    "impersonated_account": ["ImpersonatedAccount", "TargetUser"],
    "parent_integrity": ["ParentIntegrityLevel"],

    "dll_name": ["Name", "BaseDllName", "ModuleName"],
    "dll_path": ["Path", "FullDllName", "ImagePathName"],
    "dll_signed": ["Signed", "SignatureStatus", "IsSigned"],
    "dll_in_peb": ["InPEB", "InLoad", "InInit"],
    "dll_load_time": ["LoadTime", "TimeDateStamp"],
    "dll_size": ["SizeOfImage", "Size"],

    "proc_integrity": ["IntegrityLevel", "Integrity"],
    "proc_wow64": ["Wow64", "IsWow64"],
    "proc_debugger": ["HasAttachedDebugger", "Debugged", "BeingDebugged"],
    "proc_peb_mismatch": ["PebDllMismatch", "PebMismatch"],
    "proc_image_path": ["ImagePathName", "Path", "ImageFileName"],
    "proc_command_line": ["CommandLine", "Cmdline"],
    "proc_aslr": ["ASLR", "AslrEnabled"],
    "proc_dep": ["DEP", "NXCompat", "DepEnabled"],
    "proc_env": ["Environment", "EnvironmentVariables"],

    "net_pid": ["Pid", "OwningPid"],
    "net_local_addr": ["LocalAddr", "LocalAddress", "LAddr"],
    "net_local_port": ["LocalPort", "LPort"],
    "net_remote_addr": ["RemoteAddr", "ForeignAddr", "RAddr"],
    "net_remote_port": ["RemotePort", "ForeignPort", "RPort"],
    "net_state": ["State", "SocketState"],
    "net_proto": ["Protocol", "Proto"],
    "net_created": ["Created", "CreateTime"],

    "ps_pid": ["Pid", "PID"],
    "ps_ppid": ["Ppid", "PPID", "ParentPid"],
    "ps_name": ["ImageFileName", "Name", "ProcessName"],
    "ps_create_time": ["CreateTime", "ProcessCreateTime"],
    "ps_command_line": ["CommandLine", "Cmdline"],
    "ps_path": ["Path", "ImagePathName"],

    "drv_name": ["Name", "DriverName"],
    "drv_path": ["Path", "FullDllName", "DriverPath"],
    "drv_signed": ["Signed", "IsSigned", "SignatureStatus"],
    "drv_size": ["Size", "SizeOfImage"],
    "drv_hidden": ["Hidden", "IsHidden"],
    "drv_section_protection": ["Protection", "SectionProtection"],

    "vad_start": ["Start", "StartVpn", "BaseAddress"],
    "vad_end": ["End", "EndVpn"],
    "vad_protection": ["Protection"],
    "vad_tag": ["Tag"],
    "vad_file": ["Filename", "File", "MappedFile"],
    "vad_private": ["PrivateMemory", "Private"],
}


# ---------------------------------------------------------------------------
# 1. MUTEX
# ---------------------------------------------------------------------------

def extract_mutex(pid, records, ctx):
    names = [str(get_field(r, F["mutex_name"], "")) for r in records]
    names = [n for n in names if n is not None]
    global_counts = ctx["mutex_name_global_counts"]
    pid_sets_per_name = ctx["mutex_name_pid_sets"]

    per_mutex = []
    for n in names:
        clean = n.strip()
        entropy = shannon_entropy(clean)
        per_mutex.append({
            "mutex_name": clean,
            "mutex_name_length": len(clean),
            "empty_mutex_name": clean == "",
            "global_mutex_flag": clean.lower().startswith("global\\"),
            "mutex_name_entropy": round(entropy, 3),
            "guid_shaped_mutex": bool(GUID_RE.match(clean.split("\\")[-1])) if clean else False,
            "known_malware_mutex": any(sub.lower() in clean.lower() for sub in ctx["known_malware_mutex"]),
            "duplicate_mutex_across_pids": len(pid_sets_per_name.get(clean, set())) > 1,
            "rare_mutex_name": global_counts.get(clean, 0) <= 1,
        })

    return {
        "mutex_count": len(names),
        "mutexes": per_mutex,
    }


# ---------------------------------------------------------------------------
# 2. THREADS
# ---------------------------------------------------------------------------

def extract_threads(pid, records, ctx):
    thread_count = len(records)
    anonymous_memory = 0
    foreign_process = 0
    start_addr_anomaly = 0
    suspended = 0
    priority_anomaly = 0
    no_module = 0
    remote_thread = 0
    rwx = 0
    lifetimes = []

    for r in records:
        module = get_field(r, F["thread_module"])
        if not module:
            no_module += 1
            anonymous_memory += 1

        owning_pid = get_field(r, F["thread_owning_pid"])
        if owning_pid is not None and str(owning_pid) != str(pid):
            foreign_process += 1
            remote_thread += 1

        state = str(get_field(r, F["thread_state"], "")).lower()
        if "suspend" in state:
            suspended += 1

        suspend_ct = as_int(get_field(r, F["thread_suspend_count"]))
        if suspend_ct and suspend_ct > 0:
            suspended += 1

        priority = as_int(get_field(r, F["thread_priority"]))
        if priority is not None and priority >= 13:
            priority_anomaly += 1

        protection = str(get_field(r, F["thread_protection"], "")).upper()
        if "RWX" in protection or ("READWRITE" in protection and "EXECUTE" in protection):
            rwx += 1

        start_addr = get_field(r, F["thread_start_addr"])
        if start_addr and not module:
            start_addr_anomaly += 1

        ct = get_field(r, F["thread_create_time"])
        et = get_field(r, F["thread_exit_time"])
        if ct and et:
            lifetimes.append((ct, et))

    return {
        "thread_count": thread_count,
        "anonymous_memory_thread_count": anonymous_memory,
        "thread_in_foreign_process": foreign_process > 0,
        "thread_start_address_anomaly_count": start_addr_anomaly,
        "suspended_thread_count": suspended,
        "thread_priority_anomaly_count": priority_anomaly,
        "thread_with_no_module_count": no_module,
        "remote_thread_flag": remote_thread > 0,
        "rwx_execution_count": rwx,
        "thread_created_at_runtime": None,
        "thread_lifetime_pairs": lifetimes,
    }


# ---------------------------------------------------------------------------
# 3. HANDLES
# ---------------------------------------------------------------------------

SENSITIVE_HANDLE_NAMES = ["lsass", "sam", "security", "system"]
SENSITIVE_REGISTRY_HIVES = ["sam", "security", "las"]


def extract_handles(pid, records, ctx):
    handle_count = len(records)
    type_dist = Counter()
    sensitive_access = 0
    open_lsass = False
    invalid_handles = 0
    cross_process = 0
    file_in_temp = 0
    handle_to_system = 0
    sensitive_registry = 0
    named_pipes = 0
    session_handles = 0
    event_handles = 0
    token_handles = 0

    for r in records:
        htype = str(get_field(r, F["handle_type"], "")).strip()
        type_dist[htype] += 1
        hname = str(get_field(r, F["handle_name"], "")).lower()

        if any(s in hname for s in SENSITIVE_HANDLE_NAMES):
            sensitive_access += 1
        if "lsass" in hname:
            open_lsass = True
        if get_field(r, F["handle_value"]) in (None, "", "0x0", "0"):
            invalid_handles += 1

        src_pid = get_field(r, F["handle_source_pid"])
        if src_pid is not None and str(src_pid) != str(pid):
            cross_process += 1

        if htype.lower() == "file" and is_temp_or_appdata(hname):
            file_in_temp += 1

        if "wininit" in hname or hname.strip() == "system":
            handle_to_system += 1

        if any(hive in hname for hive in SENSITIVE_REGISTRY_HIVES) and "registry" in htype.lower():
            sensitive_registry += 1

        if htype.lower() in ("file",) and hname.startswith("\\pipe\\"):
            named_pipes += 1
        elif "\\pipe\\" in hname:
            named_pipes += 1

        if htype.lower() == "section" or "session" in htype.lower():
            session_handles += 1
        if htype.lower() == "event":
            event_handles += 1
        if htype.lower() == "token":
            token_handles += 1

    return {
        "handle_count": handle_count,
        "handle_count_spike": None,
        "sensitive_handle_access_count": sensitive_access,
        "handle_type_distribution": dict(type_dist),
        "invalid_handle_reference_count": invalid_handles,
        "open_lsass_handle": open_lsass,
        "cross_process_handle_count": cross_process,
        "file_handle_in_temp_count": file_in_temp,
        "handle_to_system_count": handle_to_system,
        "sensitive_registry_files_count": sensitive_registry,
        "named_pipe_count": named_pipes,
        "session_handle_count": session_handles,
        "event_handle_count": event_handles,
        "token_handle_count": token_handles,
        "system_handle_anomaly": None,
    }


# ---------------------------------------------------------------------------
# 4. IMPERSONATION
# ---------------------------------------------------------------------------

PRIVILEGE_FLAGS = {
    "has_debug_privilege": "SeDebugPrivilege",
    "has_take_ownership": "SeTakeOwnershipPrivilege",
    "has_tcb_privilege": "SeTcbPrivilege",
    "has_restore_privilege": "SeRestorePrivilege",
    "has_load_driver_privilege": "SeLoadDriverPrivilege",
}


def extract_impersonation(pid, records, ctx):
    if not records:
        return {
            "token_type": None, "integrity_level_impersonation": None, "sid_mismatch": None,
            "impersonated_account": None, "token_duplication": None,
            **{k: None for k in PRIVILEGE_FLAGS}, "token_user_mismatch": None,
            "token_source_anomaly": None, "network_logon_token": None,
        }

    out_records = []
    for r in records:
        privileges = get_field(r, F["token_privileges"], [])
        if isinstance(privileges, str):
            priv_list = [p.strip() for p in re.split(r"[;,]", privileges)]
        elif isinstance(privileges, list):
            priv_list = privileges
        else:
            priv_list = []

        token_type = str(get_field(r, F["token_type"], "")).lower()
        integrity = get_field(r, F["token_integrity"])
        parent_integrity = get_field(r, F["parent_integrity"])
        token_sid = get_field(r, F["token_sid"])
        process_sid = get_field(r, F["process_sid"])
        logon_type = str(get_field(r, F["token_logon_type"], "")).lower()

        rec_out = {
            "token_type": token_type or None,
            "integrity_level_impersonation": (
                integrity is not None and parent_integrity is not None and integrity != parent_integrity
            ) if (integrity is not None and parent_integrity is not None) else None,
            "sid_mismatch": (token_sid != process_sid) if (token_sid and process_sid) else None,
            "impersonated_account": get_field(r, F["impersonated_account"]),
            "token_duplication": as_bool(get_field(r, F["token_duplicated"])),
            "token_user_mismatch": None,
            "token_source_anomaly": None,
            "network_logon_token": "network" in logon_type if logon_type else None,
        }
        for feat_key, priv_name in PRIVILEGE_FLAGS.items():
            rec_out[feat_key] = any(priv_name.lower() in str(p).lower() for p in priv_list)
        out_records.append(rec_out)

    collapsed = {"tokens": out_records}
    for key in ("token_type", "impersonated_account"):
        collapsed[key] = out_records[0][key]
    for key in list(PRIVILEGE_FLAGS.keys()) + [
        "integrity_level_impersonation", "sid_mismatch", "token_duplication",
        "token_user_mismatch", "token_source_anomaly", "network_logon_token",
    ]:
        vals = [t[key] for t in out_records if t[key] is not None]
        collapsed[key] = any(vals) if vals else None
    return collapsed


# ---------------------------------------------------------------------------
# 5. DLLS
# ---------------------------------------------------------------------------

def homoglyph_suspect(name: str) -> bool:
    return bool(re.search(r"[0-9](?=[a-zA-Z])|(?<=[a-zA-Z])[0-9]", name)) and name.lower() not in DEFAULT_KNOWN_SYSTEM_DLLS


def extract_dlls(pid, records, ctx):
    dll_count = len(records)
    per_dll = []
    load_times = []

    for r in records:
        name = str(get_field(r, F["dll_name"], "")).strip()
        path = str(get_field(r, F["dll_path"], "")).strip()
        signed = as_bool(get_field(r, F["dll_signed"]))
        in_peb = as_bool(get_field(r, F["dll_in_peb"]))
        load_time = get_field(r, F["dll_load_time"])
        if load_time:
            load_times.append(load_time)

        per_dll.append({
            "name": name,
            "unsigned_dll": (signed is False),
            "dll_path_entropy": round(shannon_entropy(path), 3) if path else None,
            "dll_from_temp_appdata": is_temp_or_appdata(path),
            "missing_from_peb_reflective_indicator": (in_peb is False),
            "dll_not_in_known_list": name.lower() not in ctx["known_dll_baseline"] if name else None,
            "dll_name_spoof_suspect": homoglyph_suspect(name) if name else False,
            "dll_zero_time_stamp": load_time in (0, "0", None, ""),
        })

    return {
        "dll_count": dll_count,
        "dll_loaded_before_system": None,
        "dlls": per_dll,
    }


# ---------------------------------------------------------------------------
# 6. PROCESS MEMORY INFO
# ---------------------------------------------------------------------------

def extract_procinfo(pid, record, ctx):
    if not record:
        return {k: None for k in (
            "integrity_level", "is_wow64", "has_attached_debugger", "peb_dll_mismatch",
            "loading_from_temp_or_appdata", "image_path_command_line_mismatch",
            "aslr_disabled", "dep_disabled", "environment_variable_abuse",
        )}

    image_path = str(get_field(record, F["proc_image_path"], ""))
    cmdline = str(get_field(record, F["proc_command_line"], ""))
    aslr = as_bool(get_field(record, F["proc_aslr"]))
    dep = as_bool(get_field(record, F["proc_dep"]))

    return {
        "integrity_level": get_field(record, F["proc_integrity"]),
        "is_wow64": as_bool(get_field(record, F["proc_wow64"])),
        "has_attached_debugger": as_bool(get_field(record, F["proc_debugger"])),
        "peb_dll_mismatch": as_bool(get_field(record, F["proc_peb_mismatch"])),
        "loading_from_temp_or_appdata": is_temp_or_appdata(image_path),
        "image_path_command_line_mismatch": (
            bool(image_path) and bool(cmdline) and image_path.lower() not in cmdline.lower()
        ) if image_path and cmdline else None,
        "aslr_disabled": (aslr is False) if aslr is not None else None,
        "dep_disabled": (dep is False) if dep is not None else None,
        "environment_variable_abuse": None,
    }


# ---------------------------------------------------------------------------
# 7. NETSTAT
# ---------------------------------------------------------------------------

def extract_netstat(pid, records, ctx):
    conn_count = len(records)
    listening = 0
    suspicious_port_hits = []
    ephemeral_listener = 0
    foreign_ips = set()
    loopback = 0
    state_dist = Counter()
    dns_nonstandard = 0

    for r in records:
        state = str(get_field(r, F["net_state"], "")).upper()
        state_dist[state] += 1
        if "LISTEN" in state:
            listening += 1

        lport = as_int(get_field(r, F["net_local_port"]))
        rport = as_int(get_field(r, F["net_remote_port"]))
        raddr = str(get_field(r, F["net_remote_addr"], ""))
        laddr = str(get_field(r, F["net_local_addr"], ""))

        for p in (lport, rport):
            if p in SUSPICIOUS_PORTS:
                suspicious_port_hits.append(p)

        if "LISTEN" in state and lport and lport > 49152:
            ephemeral_listener += 1

        if raddr and not is_private_ip(raddr):
            foreign_ips.add(raddr)

        if raddr.startswith("127.") or laddr.startswith("127."):
            loopback += 1

        proc_name = str(get_field(r, ["ProcessName", "Owner"], "")).lower()
        if rport == 53 and proc_name and "dns" not in proc_name and "svchost" not in proc_name:
            dns_nonstandard += 1

    return {
        "has_network_connection": conn_count > 0,
        "connection_count": conn_count,
        "listening_port_count": listening,
        "suspicious_port_flag": len(suspicious_port_hits) > 0,
        "suspicious_ports_hit": sorted(set(suspicious_port_hits)),
        "ephemeral_listener_count": ephemeral_listener,
        "foreign_ip_count": len(foreign_ips),
        "multiple_foreign_countries": None,
        "loopback_connection_count": loopback,
        "state_distribution": dict(state_dist),
        "dns_over_nonstandard_count": dns_nonstandard,
        "connection_duration": None,
    }


# ---------------------------------------------------------------------------
# 8. PSLIST
# ---------------------------------------------------------------------------

def extract_pslist(pid, record, ctx):
    if not record:
        return {k: None for k in (
            "process_name_entropy", "parent_child_mismatch", "orphan_process_flag",
            "process_age_seconds", "process_depth", "commandline_empty",
            "commandline_has_base64", "commandline_has_url", "commandline_length",
        )}

    name = str(get_field(record, F["ps_name"], ""))
    ppid = get_field(record, F["ps_ppid"])
    cmdline = str(get_field(record, F["ps_command_line"], ""))

    parent_name = None
    if ppid is not None:
        parent_proc = ctx["all_processes"].get(str(ppid))
        if parent_proc and parent_proc.get("pslist"):
            parent_name = str(get_field(parent_proc["pslist"], F["ps_name"], "")).lower()

    expected_parents = EXPECTED_PARENTS.get(name.lower())
    parent_child_mismatch = None
    if expected_parents is not None and parent_name is not None:
        parent_child_mismatch = parent_name not in expected_parents

    orphan = None
    if ppid is not None:
        orphan = str(ppid) not in ctx["all_processes"] and str(pid) != "4"

    return {
        "process_name_entropy": round(shannon_entropy(name), 3) if name else None,
        "parent_child_mismatch": parent_child_mismatch,
        "orphan_process_flag": orphan,
        "process_age_seconds": None,
        "process_depth": ctx["depth_map"].get(str(pid)),
        "commandline_empty": (cmdline.strip() == ""),
        "commandline_has_base64": bool(BASE64_RE.search(cmdline)) if cmdline else False,
        "commandline_has_url": bool(URL_RE.search(cmdline)) if cmdline else False,
        "commandline_length": len(cmdline),
    }


def compute_depth_map(all_processes: dict) -> dict:
    ppid_of = {}
    for pid_str, proc in all_processes.items():
        pslist = proc.get("pslist")
        ppid = get_field(pslist, F["ps_ppid"]) if pslist else None
        ppid_of[pid_str] = str(ppid) if ppid is not None else None

    depth = {}

    def resolve(pid_str, seen):
        if pid_str in depth:
            return depth[pid_str]
        if pid_str in seen:
            return 0
        seen.add(pid_str)
        parent = ppid_of.get(pid_str)
        if parent is None or parent not in all_processes or parent == pid_str:
            depth[pid_str] = 0
        else:
            depth[pid_str] = resolve(parent, seen) + 1
        return depth[pid_str]

    for p in all_processes:
        resolve(p, set())
    return depth


# ---------------------------------------------------------------------------
# 9. DRIVERS
# ---------------------------------------------------------------------------

def extract_drivers(records, ctx):
    driver_count = len(records)
    unsigned = 0
    hidden = 0
    rwx_sections = 0
    per_driver = []
    sizes = []

    for r in records:
        name = str(get_field(r, F["drv_name"], ""))
        path = str(get_field(r, F["drv_path"], ""))
        signed = as_bool(get_field(r, F["drv_signed"]))
        hidden_flag = as_bool(get_field(r, F["drv_hidden"]))
        size = as_int(get_field(r, F["drv_size"]))
        protection = str(get_field(r, F["drv_section_protection"], "")).upper()

        if signed is False:
            unsigned += 1
        if hidden_flag:
            hidden += 1
        if "RWX" in protection or ("READWRITE" in protection and "EXECUTE" in protection):
            rwx_sections += 1
        if size:
            sizes.append(size)

        per_driver.append({
            "name": name,
            "unsigned_driver": (signed is False),
            "driver_path_anomaly": is_temp_or_appdata(path),
            "hidden_driver": bool(hidden_flag),
            "driver_name_anomaly": homoglyph_suspect(name) if name else False,
            "rwx_driver_section": "RWX" in protection or ("READWRITE" in protection and "EXECUTE" in protection),
            "driver_size_anomaly": None,
        })

    return {
        "driver_count_per_snapshot": driver_count,
        "unsigned_driver_count": unsigned,
        "hidden_driver_count": hidden,
        "rwx_driver_section_count": rwx_sections,
        "drivers": per_driver,
    }


# ---------------------------------------------------------------------------
# 10. VAD
# ---------------------------------------------------------------------------

def extract_vad(pid, records, ctx):
    vad_count = len(records)
    private_rwx = 0
    no_file_backing = 0
    per_vad = []

    for r in records:
        protection = str(get_field(r, F["vad_protection"], "")).upper()
        private_mem = as_bool(get_field(r, F["vad_private"]))
        filename = get_field(r, F["vad_file"])

        is_rwx = "RWX" in protection or ("EXECUTE_READWRITE" in protection)
        is_private_rwx = bool(is_rwx and private_mem)
        if is_private_rwx:
            private_rwx += 1
        if not filename:
            no_file_backing += 1

        per_vad.append({
            "start": get_field(r, F["vad_start"]),
            "end": get_field(r, F["vad_end"]),
            "protection": protection or None,
            "private_memory": private_mem,
            "file_backed": bool(filename),
            "private_rwx_region": is_private_rwx,
        })

    return {
        "vad_count": vad_count,
        "private_rwx_region_count": private_rwx,
        "no_file_backing_count": no_file_backing,
        "vads": per_vad,
    }


# ---------------------------------------------------------------------------
# Orchestration (extract stage)
# ---------------------------------------------------------------------------

def build_context(all_processes: dict, known_malware_mutex, known_dll_baseline):
    mutex_name_global_counts = Counter()
    mutex_name_pid_sets = defaultdict(set)

    for pid_str, proc in all_processes.items():
        for r in proc.get("mutex", []):
            name = str(get_field(r, F["mutex_name"], "")).strip()
            if not name:
                continue
            mutex_name_global_counts[name] += 1
            mutex_name_pid_sets[name].add(pid_str)

    depth_map = compute_depth_map(all_processes)

    return {
        "all_processes": all_processes,
        "mutex_name_global_counts": mutex_name_global_counts,
        "mutex_name_pid_sets": mutex_name_pid_sets,
        "depth_map": depth_map,
        "known_malware_mutex": known_malware_mutex,
        "known_dll_baseline": known_dll_baseline,
    }


def load_list_file(path, default):
    if not path:
        return default
    p = Path(path)
    if not p.exists():
        print(f"[!] Reference list not found: {path} -- using built-in default", file=sys.stderr)
        return default
    return [line.strip().lower() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def extract_features(merged: dict, out_path: str, known_mutex_path=None, known_dll_path=None):
    """
    Takes the merged dict DIRECTLY (as returned in-memory by merge()) --
    no re-read of the merged JSON file from disk required.
    """
    all_processes = merged.get("processes", {})
    unattributed = merged.get("unattributed", {})

    known_malware_mutex = load_list_file(
        known_mutex_path, DEFAULT_KNOWN_MALWARE_MUTEX_SUBSTRINGS
    )
    known_dll_baseline = set(
        load_list_file(known_dll_path, list(DEFAULT_KNOWN_SYSTEM_DLLS))
    )

    ctx = build_context(all_processes, known_malware_mutex, known_dll_baseline)

    output = {"processes": {}, "global": {}}

    for pid_str, proc in all_processes.items():
        output["processes"][pid_str] = {
            "pid": pid_str,
            "ppid": proc.get("ppid"),
            "mutex_features": extract_mutex(pid_str, proc.get("mutex", []), ctx),
            "thread_features": extract_threads(pid_str, proc.get("threads", []), ctx),
            "handle_features": extract_handles(pid_str, proc.get("handles", []), ctx),
            "impersonation_features": extract_impersonation(pid_str, proc.get("impersonation", []), ctx),
            "dll_features": extract_dlls(pid_str, proc.get("dlls", []), ctx),
            "procinfo_features": extract_procinfo(pid_str, proc.get("procinfo"), ctx),
            "netstat_features": extract_netstat(pid_str, proc.get("netstat", []), ctx),
            "pslist_features": extract_pslist(pid_str, proc.get("pslist"), ctx),
            "vad_features": extract_vad(pid_str, proc.get("vad", []), ctx),
        }

    all_driver_records = list(unattributed.get("drivers", []))
    for proc in all_processes.values():
        all_driver_records.extend(proc.get("drivers", []))

    output["global"]["driver_features"] = extract_drivers(all_driver_records, ctx)

    Path(out_path).write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")

    print(f"[OK] Wrote features for {len(all_processes)} process(es) -> {out_path}")

    return output


# =============================================================================
# =====================  STAGE 3: BASELINE COMPARE  ===========================
# (from baseline_compare.py -- logic unchanged)
# =============================================================================

# NOTE: baseline_compare.py originally defined its own local get_field()
# (NAME_CANDIDATES-based). extract_features.py already defines a more
# general get_field() above with the same signature/behavior, so it is
# reused here as-is -- no logic difference for what this stage needs
# (case-sensitive-first then case-insensitive lookup over a candidate list).

NAME_CANDIDATES = ["ImageFileName", "Name", "ProcessName"]


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Identity resolution (PID -> process name), using the merged file if given
# ---------------------------------------------------------------------------

def build_pid_to_name(merged_data):
    """pid_str -> image name, or None if no merged file / no pslist record."""
    if not merged_data:
        return {}
    out = {}
    for pid, proc in merged_data.get("processes", {}).items():
        pslist = proc.get("pslist")
        name = get_field(pslist, NAME_CANDIDATES) if pslist else None
        if name:
            out[pid] = str(name).strip()
    return out


def build_pid_to_ppid(merged_data):
    if not merged_data:
        return {}
    out = {}
    for pid, proc in merged_data.get("processes", {}).items():
        pslist = proc.get("pslist")
        ppid = get_field(pslist, ["Ppid", "PPID", "ParentPid"]) if pslist else None
        if ppid is not None:
            out[pid] = str(ppid)
    return out


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def match_processes(base_features, cur_features, base_names, cur_names):
    """Returns (matched_pairs, new_pids, terminated_pids)
    matched_pairs: list of (base_pid, cur_pid, match_type, name)
    new_pids: list of cur_pid present only in "current"
    terminated_pids: list of base_pid present only in "baseline"
    """
    base_pids = set(base_features.get("processes", {}).keys())
    cur_pids = set(cur_features.get("processes", {}).keys())

    matched = []
    exact = base_pids & cur_pids
    for pid in exact:
        matched.append((pid, pid, "pid_exact", base_names.get(pid) or cur_names.get(pid) or f"<pid:{pid}>"))

    remaining_base = base_pids - exact
    remaining_cur = cur_pids - exact

    # group remaining by name (only possible where merged files were given)
    base_by_name = defaultdict(list)
    for pid in sorted(remaining_base, key=lambda p: (int(p) if p.isdigit() else 0)):
        base_by_name[base_names.get(pid, f"<unknown:{pid}>")].append(pid)

    cur_by_name = defaultdict(list)
    for pid in sorted(remaining_cur, key=lambda p: (int(p) if p.isdigit() else 0)):
        cur_by_name[cur_names.get(pid, f"<unknown:{pid}>")].append(pid)

    new_pids = []
    terminated_pids = []

    all_names = set(base_by_name) | set(cur_by_name)
    for name in all_names:
        b_list = base_by_name.get(name, [])
        c_list = cur_by_name.get(name, [])
        paired = min(len(b_list), len(c_list))
        for i in range(paired):
            matched.append((b_list[i], c_list[i], "name_paired", name))
        # extra current instances beyond what baseline had = new instances
        for pid in c_list[paired:]:
            new_pids.append(pid)
        # extra baseline instances beyond what current has = terminated
        for pid in b_list[paired:]:
            terminated_pids.append(pid)

    return matched, new_pids, terminated_pids


# ---------------------------------------------------------------------------
# Generic feature-tree diff
# ---------------------------------------------------------------------------

LIST_ENTITY_NAME_KEY = {
    "mutexes": "mutex_name",
    "dlls": "name",
    "drivers": "name",
}


def diff_leaf_tree(base_block, cur_block, path=""):
    """Recursively diffs two feature dicts (e.g. one process's
    'handle_features' block against its counterpart). Skips list-valued
    keys -- those are diffed separately as named-entity sets."""
    result = {"risk_flags_activated": [], "risk_flags_deactivated": [],
              "count_changes": [], "value_changes": []}
    if not isinstance(base_block, dict):
        base_block = {}
    if not isinstance(cur_block, dict):
        cur_block = {}

    keys = set(base_block.keys()) | set(cur_block.keys())
    for k in keys:
        bv = base_block.get(k)
        cv = cur_block.get(k)
        full_key = f"{path}.{k}" if path else k

        if isinstance(bv, list) or isinstance(cv, list):
            continue  # handled by diff_named_entities

        if isinstance(bv, dict) or isinstance(cv, dict):
            sub = diff_leaf_tree(bv if isinstance(bv, dict) else {},
                                  cv if isinstance(cv, dict) else {}, full_key)
            for kk in result:
                result[kk].extend(sub[kk])
            continue

        if isinstance(bv, bool) or isinstance(cv, bool):
            bv_b, cv_b = bool(bv), bool(cv)
            if not bv_b and cv_b:
                result["risk_flags_activated"].append(full_key)
            elif bv_b and not cv_b:
                result["risk_flags_deactivated"].append(full_key)
            continue

        if isinstance(bv, (int, float)) or isinstance(cv, (int, float)):
            b_num = bv if isinstance(bv, (int, float)) else 0
            c_num = cv if isinstance(cv, (int, float)) else 0
            if b_num != c_num:
                result["count_changes"].append({
                    "field": full_key, "baseline": b_num, "current": c_num,
                    "delta": c_num - b_num,
                })
            continue

        if bv != cv:
            result["value_changes"].append({"field": full_key, "baseline": bv, "current": cv})

    return result


def diff_named_entities(base_proc_features, cur_proc_features):
    """For mutexes/dlls/drivers (list of dicts with a name-like key),
    return the set of entities that appear in 'current' but not in
    'baseline', keyed by category. Only compares by name -- not full
    record equality -- since load order / minor fields will differ
    between snapshots even for an unchanged entity."""
    new_entities = {}
    category_map = {
        "mutex_features": ("mutexes", "mutex_name"),
        "dll_features": ("dlls", "name"),
    }
    for feat_key, (list_key, name_key) in category_map.items():
        base_list = (base_proc_features.get(feat_key) or {}).get(list_key, []) or []
        cur_list = (cur_proc_features.get(feat_key) or {}).get(list_key, []) or []
        base_names = {str(e.get(name_key, "")) for e in base_list if isinstance(e, dict)}
        cur_by_name = {str(e.get(name_key, "")): e for e in cur_list if isinstance(e, dict)}
        new_names = set(cur_by_name) - base_names
        if new_names:
            new_entities[feat_key] = [cur_by_name[n] for n in sorted(new_names) if n]
    return new_entities


SPIKE_FIELDS_SUFFIX = "_count"  # any numeric field ending in _count is a spike candidate


def mark_spikes(count_changes, multiplier, min_delta):
    for c in count_changes:
        b, cnew, delta = c["baseline"], c["current"], c["delta"]
        is_count_field = c["field"].split(".")[-1].endswith(SPIKE_FIELDS_SUFFIX)
        spike = False
        if is_count_field and delta > 0:
            if b <= 0:
                spike = cnew >= min_delta
            else:
                spike = (cnew >= b * multiplier) and (delta >= min_delta)
        c["spike"] = spike
    return count_changes


# ---------------------------------------------------------------------------
# Per-process comparison
# ---------------------------------------------------------------------------

FEATURE_BLOCK_KEYS = [
    "mutex_features", "thread_features", "handle_features",
    "impersonation_features", "dll_features", "procinfo_features",
    "netstat_features", "pslist_features", "vad_features",
]


def score_diff(diff, new_entities, ppid_changed):
    score = 0
    score += 3 * len(diff["risk_flags_activated"])
    score += 5 * sum(1 for c in diff["count_changes"] if c.get("spike"))
    score += 1 * sum(1 for c in diff["count_changes"] if not c.get("spike") and c["delta"] > 0)
    for feat_key, entities in new_entities.items():
        weight = 4
        if feat_key == "mutex_features":
            for e in entities:
                if e.get("known_malware_mutex"):
                    weight += 6
                if e.get("guid_shaped_mutex"):
                    weight += 1
        if feat_key == "dll_features":
            for e in entities:
                if e.get("unsigned_dll") or e.get("dll_from_temp_appdata") or e.get("dll_name_spoof_suspect"):
                    weight += 3
        score += weight * len(entities)
    if ppid_changed:
        score += 3
    return score


def compare_process(base_proc, cur_proc, base_ppid, cur_ppid):
    diff = {"risk_flags_activated": [], "risk_flags_deactivated": [],
            "count_changes": [], "value_changes": []}
    for block in FEATURE_BLOCK_KEYS:
        sub = diff_leaf_tree(base_proc.get(block), cur_proc.get(block), path=block)
        for k in diff:
            diff[k].extend(sub[k])

    new_entities = diff_named_entities(base_proc, cur_proc)
    ppid_changed = bool(base_ppid and cur_ppid and base_ppid != cur_ppid)

    return diff, new_entities, ppid_changed


def summarize_new_process(cur_proc):
    """A brand-new process has no baseline to diff against -- surface
    whatever intrinsic risk flags/entities it already carries."""
    flags = []
    for block in FEATURE_BLOCK_KEYS:
        b = cur_proc.get(block) or {}
        for k, v in b.items():
            if isinstance(v, bool) and v:
                flags.append(f"{block}.{k}")
    suspicious_mutexes = [m for m in (cur_proc.get("mutex_features") or {}).get("mutexes", [])
                           if m.get("known_malware_mutex")]
    suspicious_dlls = [d for d in (cur_proc.get("dll_features") or {}).get("dlls", [])
                        if d.get("unsigned_dll") or d.get("dll_from_temp_appdata")]
    return flags, suspicious_mutexes, suspicious_dlls


# ---------------------------------------------------------------------------
# Baseline-compare orchestration
# ---------------------------------------------------------------------------

def baseline_compare(base_features, cur_features, base_merged, cur_merged, out_path,
                      spike_multiplier=2.0, spike_min_delta=5, top_n=15):
    """
    Takes the PRE (baseline) and DURING (current) merged + features dicts
    DIRECTLY as already-in-memory objects (as returned by merge() and
    extract_features() above) -- no re-read of pre_merged.json /
    during_merged.json / pre_features.json / during_features.json from
    disk required.
    """
    if not base_merged or not cur_merged:
        print("[!] No merged data provided -- matching will be PID-only")

    # ---- BUILD LOOKUPS ----
    base_names = build_pid_to_name(base_merged)
    cur_names = build_pid_to_name(cur_merged)
    base_ppids = build_pid_to_ppid(base_merged)
    cur_ppids = build_pid_to_ppid(cur_merged)

    matched, new_pids, terminated_pids = match_processes(
        base_features, cur_features, base_names, cur_names
    )

    # ---- COMPARE MATCHED PROCESSES ----
    process_results = []

    for base_pid, cur_pid, match_type, name in matched:
        base_proc = base_features["processes"][base_pid]
        cur_proc = cur_features["processes"][cur_pid]

        diff, new_entities, ppid_changed = compare_process(
            base_proc, cur_proc,
            base_ppids.get(base_pid),
            cur_ppids.get(cur_pid)
        )

        mark_spikes(diff["count_changes"], spike_multiplier, spike_min_delta)
        score = score_diff(diff, new_entities, ppid_changed)

        process_results.append({
            "name": name,
            "baseline_pid": base_pid,
            "current_pid": cur_pid,
            "match_type": match_type,
            "ppid_changed": ppid_changed,
            "anomaly_score": score,
            "risk_flags_activated": diff["risk_flags_activated"],
            "risk_flags_deactivated": diff["risk_flags_deactivated"],
            "count_changes": [c for c in diff["count_changes"] if c["delta"] != 0],
            "value_changes": diff["value_changes"],
            "new_entities": new_entities,
        })

    # ---- NEW PROCESSES ----
    new_process_results = []
    for pid in new_pids:
        cur_proc = cur_features["processes"][pid]
        flags, sus_mutex, sus_dll = summarize_new_process(cur_proc)

        score = 10 + 3 * len(flags) + 6 * len(sus_mutex) + 3 * len(sus_dll)

        new_process_results.append({
            "name": cur_names.get(pid, f"<unknown:{pid}>"),
            "current_pid": pid,
            "anomaly_score": score,
            "intrinsic_risk_flags": flags,
            "known_malware_mutex_hits": sus_mutex,
            "suspicious_dlls": sus_dll,
        })

    # ---- TERMINATED PROCESSES ----
    terminated_process_results = [
        {"name": base_names.get(pid, f"<unknown:{pid}>"), "baseline_pid": pid}
        for pid in terminated_pids
    ]

    # ---- DRIVER COMPARISON ----
    base_drv = (base_features.get("global") or {}).get("driver_features") or {}
    cur_drv = (cur_features.get("global") or {}).get("driver_features") or {}

    driver_diff = diff_leaf_tree(base_drv, cur_drv, path="driver_features")
    mark_spikes(driver_diff["count_changes"], spike_multiplier, spike_min_delta)

    base_driver_names = {d.get("name", "") for d in base_drv.get("drivers", []) if isinstance(d, dict)}
    cur_driver_by_name = {d.get("name", ""): d for d in cur_drv.get("drivers", []) if isinstance(d, dict)}

    new_driver_names = set(cur_driver_by_name) - base_driver_names
    new_drivers = [cur_driver_by_name[n] for n in sorted(new_driver_names) if n]

    # ---- SORT RESULTS ----
    all_scored = sorted(
        process_results + new_process_results,
        key=lambda r: r["anomaly_score"],
        reverse=True
    )

    # ---- OUTPUT ----
    output = {
        "summary": {
            "baseline_process_count": len(base_features.get("processes", {})),
            "current_process_count": len(cur_features.get("processes", {})),
            "matched_process_count": len(process_results),
            "new_process_count": len(new_process_results),
            "terminated_process_count": len(terminated_process_results),
            "driver_count_baseline": base_drv.get("driver_count_per_snapshot"),
            "driver_count_current": cur_drv.get("driver_count_per_snapshot"),
            "new_driver_count": len(new_drivers),
        },
        "matched_processes": process_results,
        "new_processes": new_process_results,
        "terminated_processes": terminated_process_results,
        "driver_baseline_delta": {
            "count_changes": driver_diff["count_changes"],
            "risk_flags_activated": driver_diff["risk_flags_activated"],
            "new_drivers": new_drivers,
        },
    }

    Path(out_path).write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")

    print(f"[OK] Wrote baseline comparison -> {out_path}")
    print(f"Baseline: {output['summary']['baseline_process_count']} | Current: {output['summary']['current_process_count']}")
    print(f"Matched: {output['summary']['matched_process_count']} | New: {output['summary']['new_process_count']} | Terminated: {output['summary']['terminated_process_count']}")

    print(f"\n[Top {top_n} anomalies]")
    for r in all_scored[:top_n]:
        pid_label = r.get("current_pid") or r.get("baseline_pid")
        print(f"score={r['anomaly_score']:>4} pid={pid_label:<8} name={r['name']}")

    return output


# =============================================================================
# ======================  STAGE 4: ANOMALY SCORING  ===========================
# (from the z-score scoring module -- logic unchanged)
# =============================================================================

def flatten_features(process_data):
    flat = {}

    for section, values in process_data.items():
        if isinstance(values, dict):
            for k, v in values.items():
                if isinstance(v, (int, float)):
                    flat[f"{section}.{k}"] = v

    return flat


def compute_stats(baseline):
    stats = {}

    for pid, proc in baseline["processes"].items():
        features = flatten_features(proc)

        for key, val in features.items():
            stats.setdefault(key, []).append(val)

    final_stats = {}
    for key, values in stats.items():
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(variance)

        final_stats[key] = {"mean": mean, "std": std}

    return final_stats


def score_snapshots(baseline, current):
    stats = compute_stats(baseline)
    results = []

    for pid, proc in current["processes"].items():
        features = flatten_features(proc)

        score = 0
        details = {}

        for key, val in features.items():
            if key in stats:
                mean = stats[key]["mean"]
                std = stats[key]["std"]

                if std > 0:
                    z = abs((val - mean) / std)
                else:
                    z = 0

                details[key] = z
                score += z

        results.append({
            "pid": pid,
            "score": score,
            "feature_scores": details
        })

    return results


def anomaly_score(baseline_features, current_features, out_path):
    """
    Takes the PRE (baseline) and DURING (current) features dicts DIRECTLY
    as already-in-memory objects (as returned by extract_features() above)
    -- no re-read of pre_features.json / during_features.json from disk
    required.
    """
    print("[+] Computing anomaly scores...")
    results = score_snapshots(baseline_features, current_features)

    # Sort by highest score (important!)
    results = sorted(results, key=lambda x: x["score"], reverse=True)

    Path(out_path).write_text(json.dumps(results, indent=4), encoding="utf-8")

    print(f"[OK] Scoring complete. Output saved to {out_path}")

    return results


# =============================================================================
# ======================  STAGE 5: EVIDENCE BUILDER  ==========================
# (from Evidence Builder -- logic unchanged)
# =============================================================================

# ================================================================
# Risk Levels
# ================================================================

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"


# ================================================================
# Severity Scores
# ================================================================

SEVERITY_SCORE = {

    "INFO": 0,

    "LOW": 5,

    "MEDIUM": 10,

    "HIGH": 20,

    "CRITICAL": 35

}


# ================================================================
# MITRE ATT&CK Mapping
# ================================================================

MITRE = {

    "PROCESS_INJECTION": {
        "id": "T1055",
        "name": "Process Injection"
    },

    "CREDENTIAL_DUMPING": {
        "id": "T1003",
        "name": "OS Credential Dumping"
    },

    "DLL_SIDELOADING": {
        "id": "T1574",
        "name": "DLL Side-Loading"
    },

    "COMMAND_AND_CONTROL": {
        "id": "T1071",
        "name": "Application Layer Protocol"
    },

    "REMOTE_SERVICES": {
        "id": "T1021",
        "name": "Remote Services"
    },

    "PERSISTENCE": {
        "id": "T1547",
        "name": "Boot or Logon Autostart"
    },

    "DEFENSE_EVASION": {
        "id": "T1562",
        "name": "Impair Defenses"
    }

}


# ================================================================
# Evidence Object
# ================================================================

class Evidence:

    def __init__(
        self,
        feature,
        severity,
        reason,
        why,
        mitre=None
    ):

        self.feature = feature

        self.severity = severity

        self.reason = reason

        self.why = why

        self.mitre = mitre

        self.score = SEVERITY_SCORE.get(
            severity,
            0
        )

    def to_dict(self):

        obj = {

            "feature": self.feature,

            "severity": self.severity,

            "reason": self.reason,

            "why_it_matters": self.why,

            "score": self.score

        }

        if self.mitre:

            obj["mitre"] = self.mitre

        return obj


# ================================================================
# Utility Functions
# ================================================================

def get(data, key, default=None):

    if data is None:
        return default

    return data.get(key, default)


def truthy(value):

    if isinstance(value, bool):
        return value

    if value is None:
        return False

    if isinstance(value, int):
        return value != 0

    if isinstance(value, str):

        return value.lower() in (
            "true",
            "yes",
            "1"
        )

    return bool(value)


def entropy(text):

    if not text:
        return 0

    freq = defaultdict(int)

    for c in text:
        freq[c] += 1

    length = len(text)

    e = 0

    for v in freq.values():

        p = v / length

        e -= p * math.log2(p)

    return round(e, 3)


# ================================================================
# Risk Calculation
# ================================================================

def risk_level(score):

    if score >= 80:
        return CRITICAL

    if score >= 50:
        return HIGH

    if score >= 20:
        return MEDIUM

    return LOW


def confidence(score):

    if score >= 80:
        return "Very High"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


# ================================================================
# Evidence Collector
# ================================================================

class EvidenceCollector:

    def __init__(self):

        self.items = []

        self.total_score = 0

    def add(self, evidence):

        self.items.append(evidence)

        self.total_score += evidence.score

    def extend(self, evidence_list):

        for e in evidence_list:
            self.add(e)

    def deduplicate(self):

        unique = {}

        for item in self.items:

            key = (
                item.feature,
                item.reason
            )

            unique[key] = item

        self.items = list(unique.values())

    def score(self):

        return self.total_score

    def risk(self):

        return risk_level(
            self.total_score
        )

    def confidence(self):

        return confidence(
            self.total_score
        )

    def json(self):

        return [
            e.to_dict()
            for e in self.items
        ]


# ================================================================
# Rule Engines
#
# Part 2 starts here
# ================================================================

# ================================================================
# Thread Rule Engine
# Matches extract_threads() from extract_features.py
# ================================================================

def analyze_threads(thread_features):

    collector = EvidenceCollector()

    if not thread_features:
        return collector

    thread_count = get(thread_features, "thread_count", 0)

    if thread_count > 100:

        collector.add(
            Evidence(
                feature="High Thread Count",
                severity="LOW",
                reason=f"The process created {thread_count} threads.",
                why="Processes with an unusually large number of threads may deserve further investigation."
            )
        )

    # ------------------------------------------------------------
    # Anonymous Memory Threads
    # ------------------------------------------------------------

    anonymous = get(
        thread_features,
        "anonymous_memory_thread_count",
        0
    )

    if anonymous > 0:

        collector.add(
            Evidence(
                feature="Anonymous Memory Thread",
                severity="HIGH",
                reason=f"{anonymous} thread(s) execute from anonymous memory.",
                why="Threads executing outside image-backed memory are commonly associated with injected code.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Thread Start Address Anomaly
    # ------------------------------------------------------------

    anomaly = get(
        thread_features,
        "thread_start_address_anomaly_count",
        0
    )

    if anomaly > 0:

        collector.add(
            Evidence(
                feature="Thread Start Address Anomaly",
                severity="HIGH",
                reason=f"{anomaly} thread(s) have suspicious start addresses.",
                why="Thread start addresses that do not belong to loaded modules may indicate process injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Threads without module
    # ------------------------------------------------------------

    no_module = get(
        thread_features,
        "thread_with_no_module_count",
        0
    )

    if no_module > 0:

        collector.add(
            Evidence(
                feature="Thread Without Module",
                severity="HIGH",
                reason=f"{no_module} thread(s) are not associated with any loaded module.",
                why="Execution outside a legitimate image is a common memory-injection indicator.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Remote Thread
    # ------------------------------------------------------------

    if get(thread_features, "remote_thread_flag", False):

        collector.add(
            Evidence(
                feature="Remote Thread",
                severity="CRITICAL",
                reason="A remote thread was detected.",
                why="Remote thread creation is one of the most common techniques used during process injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Foreign Process Thread
    # ------------------------------------------------------------

    if get(thread_features, "thread_in_foreign_process", False):

        collector.add(
            Evidence(
                feature="Foreign Process Thread",
                severity="HIGH",
                reason="The process owns thread(s) executing inside another process.",
                why="Threads executing in foreign processes may indicate code injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # RWX Execution
    # ------------------------------------------------------------

    rwx = get(
        thread_features,
        "rwx_execution_count",
        0
    )

    if rwx > 0:

        collector.add(
            Evidence(
                feature="RWX Thread Execution",
                severity="CRITICAL",
                reason=f"{rwx} executable read-write memory region(s) detected.",
                why="RWX memory is frequently used by shellcode and malware.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Suspended Threads
    # ------------------------------------------------------------

    suspended = get(
        thread_features,
        "suspended_thread_count",
        0
    )

    if suspended > 5:

        collector.add(
            Evidence(
                feature="Suspended Threads",
                severity="LOW",
                reason=f"{suspended} suspended thread(s) detected.",
                why="Large numbers of suspended threads may indicate process manipulation."
            )
        )

    # ------------------------------------------------------------
    # Priority Anomaly
    # ------------------------------------------------------------

    priority = get(
        thread_features,
        "thread_priority_anomaly_count",
        0
    )

    if priority > 0:

        collector.add(
            Evidence(
                feature="Abnormal Thread Priority",
                severity="MEDIUM",
                reason=f"{priority} thread(s) use unusually high priorities.",
                why="Attackers sometimes increase thread priority to ensure malicious code executes promptly."
            )
        )

    return collector

# ================================================================
# DLL Rule Engine
# Matches extract_dlls() from extract_features.py
# ================================================================

def analyze_dlls(dll_features):

    collector = EvidenceCollector()

    if not dll_features:
        return collector

    dlls = get(dll_features, "dlls", [])

    if not dlls:
        return collector

    dll_count = get(dll_features, "dll_count", len(dlls))

    if dll_count > 250:

        collector.add(
            Evidence(
                feature="High DLL Count",
                severity="LOW",
                reason=f"The process loaded {dll_count} DLLs.",
                why="An unusually large number of loaded modules may indicate abnormal execution."
            )
        )

    # ------------------------------------------------------------
    # Analyse every DLL individually
    # ------------------------------------------------------------

    unsigned = []
    temp = []
    reflective = []
    spoofed = []
    unknown = []

    entropy_hits = []

    for dll in dlls:

        name = get(dll, "name", "Unknown")

        # ------------------------------------------

        if get(dll, "unsigned_dll", False):
            unsigned.append(name)

        # ------------------------------------------

        if get(dll, "dll_from_temp_appdata", False):
            temp.append(name)

        # ------------------------------------------

        if get(
            dll,
            "missing_from_peb_reflective_indicator",
            False
        ):
            reflective.append(name)

        # ------------------------------------------

        if get(
            dll,
            "dll_name_spoof_suspect",
            False
        ):
            spoofed.append(name)

        # ------------------------------------------

        if get(
            dll,
            "dll_not_in_known_list",
            False
        ):
            unknown.append(name)

        # ------------------------------------------

        entropy = get(
            dll,
            "dll_path_entropy"
        )

        if entropy is not None and entropy >= 4.5:

            entropy_hits.append(
                f"{name} ({entropy:.2f})"
            )

    # ------------------------------------------------------------
    # Unsigned DLLs
    # ------------------------------------------------------------

    if unsigned:

        collector.add(

            Evidence(

                feature="Unsigned DLL",

                severity="HIGH",

                reason=f"{len(unsigned)} unsigned DLL(s): "
                       + ", ".join(unsigned[:5]),

                why="Unsigned DLLs may indicate DLL sideloading or malicious modules.",

                mitre=MITRE["DLL_SIDELOADING"]

            )
        )

    # ------------------------------------------------------------
    # DLLs from Temp/AppData
    # ------------------------------------------------------------

    if temp:

        collector.add(

            Evidence(

                feature="DLL Loaded From Temp",

                severity="HIGH",

                reason=f"DLL(s) loaded from Temp/AppData: "
                       + ", ".join(temp[:5]),

                why="Legitimate software rarely loads executable modules from user-writable directories.",

                mitre=MITRE["DLL_SIDELOADING"]

            )
        )

    # ------------------------------------------------------------
    # Reflective DLL Loading
    # ------------------------------------------------------------

    if reflective:

        collector.add(

            Evidence(

                feature="Reflective DLL Loading",

                severity="CRITICAL",

                reason=f"{len(reflective)} DLL(s) missing from the PEB: "
                       + ", ".join(reflective[:5]),

                why="Modules absent from the Process Environment Block may have been reflectively loaded.",

                mitre=MITRE["PROCESS_INJECTION"]

            )
        )

    # ------------------------------------------------------------
    # DLL Name Spoofing
    # ------------------------------------------------------------

    if spoofed:

        collector.add(

            Evidence(

                feature="DLL Name Spoofing",

                severity="MEDIUM",

                reason="Suspicious DLL names: "
                       + ", ".join(spoofed[:5]),

                why="Malware often mimics legitimate DLL names to evade casual inspection."

            )
        )

    # ------------------------------------------------------------
    # Unknown DLLs
    # ------------------------------------------------------------

    if unknown:

        collector.add(

            Evidence(

                feature="Unknown DLL",

                severity="LOW",

                reason=f"{len(unknown)} DLL(s) not found in the baseline list.",

                why="Modules outside the known baseline deserve additional investigation."

            )
        )

    # ------------------------------------------------------------
    # High Entropy DLL Paths
    # ------------------------------------------------------------

    if entropy_hits:

        collector.add(

            Evidence(

                feature="High Entropy DLL Path",

                severity="LOW",

                reason=", ".join(entropy_hits[:5]),

                why="Randomized directory structures are sometimes used by malware."

            )
        )

    return collector

# ================================================================
# Handle Rule Engine
# Matches extract_handles()
# ================================================================

def analyze_handles(handle_features):

    collector = EvidenceCollector()

    if not handle_features:
        return collector

    # ------------------------------------------------------------
    # LSASS Handle
    # ------------------------------------------------------------

    if get(handle_features, "open_lsass_handle", False):

        collector.add(
            Evidence(
                feature="LSASS Handle",
                severity="CRITICAL",
                reason="The process opened a handle to LSASS.",
                why="Attackers frequently access LSASS during credential dumping.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ------------------------------------------------------------

    sensitive = get(
        handle_features,
        "sensitive_handle_access_count",
        0
    )

    if sensitive > 0:

        collector.add(
            Evidence(
                feature="Sensitive Handle Access",
                severity="HIGH",
                reason=f"{sensitive} sensitive object(s) accessed.",
                why="Accessing security-sensitive objects may indicate credential theft or privilege escalation."
            )
        )

    # ------------------------------------------------------------

    cross = get(
        handle_features,
        "cross_process_handle_count",
        0
    )

    if cross > 0:

        collector.add(
            Evidence(
                feature="Cross Process Handle",
                severity="HIGH",
                reason=f"{cross} cross-process handle(s) detected.",
                why="Processes normally do not access large numbers of handles belonging to other processes."
            )
        )

    # ------------------------------------------------------------

    invalid = get(
        handle_features,
        "invalid_handle_reference_count",
        0
    )

    if invalid > 10:

        collector.add(
            Evidence(
                feature="Invalid Handle References",
                severity="LOW",
                reason=f"{invalid} invalid handles detected.",
                why="Large numbers of invalid handles may indicate unstable or malicious process behavior."
            )
        )

    # ------------------------------------------------------------

    temp = get(
        handle_features,
        "file_handle_in_temp_count",
        0
    )

    if temp > 0:

        collector.add(
            Evidence(
                feature="Temp File Handle",
                severity="MEDIUM",
                reason=f"{temp} file handle(s) point to Temp/AppData.",
                why="Malware frequently stages payloads inside user-writable directories."
            )
        )

    # ------------------------------------------------------------

    registry = get(
        handle_features,
        "sensitive_registry_files_count",
        0
    )

    if registry > 0:

        collector.add(
            Evidence(
                feature="Sensitive Registry Access",
                severity="HIGH",
                reason=f"{registry} sensitive registry hive(s) accessed.",
                why="Registry hives such as SAM and SECURITY contain credential-related information.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ------------------------------------------------------------

    pipes = get(
        handle_features,
        "named_pipe_count",
        0
    )

    if pipes > 10:

        collector.add(
            Evidence(
                feature="Named Pipe Activity",
                severity="LOW",
                reason=f"{pipes} named pipes opened.",
                why="Named pipes can be used for inter-process communication, including malware communication."
            )
        )

    return collector


# ================================================================
# Token / Impersonation Rule Engine
# Matches extract_impersonation()
# ================================================================

def analyze_tokens(token_features):

    collector = EvidenceCollector()

    if not token_features:
        return collector

    # ------------------------------------------------------------

    if get(token_features, "sid_mismatch"):

        collector.add(
            Evidence(
                feature="SID Mismatch",
                severity="HIGH",
                reason="Token SID differs from Process SID.",
                why="SID mismatches may indicate impersonation or token manipulation."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "token_duplication"):

        collector.add(
            Evidence(
                feature="Duplicated Token",
                severity="HIGH",
                reason="Duplicated access token detected.",
                why="Duplicated tokens are frequently used during privilege escalation."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "network_logon_token"):

        collector.add(
            Evidence(
                feature="Network Logon Token",
                severity="MEDIUM",
                reason="A network logon token was observed.",
                why="Unexpected network logon tokens may indicate lateral movement."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_debug_privilege"):

        collector.add(
            Evidence(
                feature="SeDebugPrivilege",
                severity="CRITICAL",
                reason="Process possesses SeDebugPrivilege.",
                why="SeDebugPrivilege allows inspection and manipulation of other processes.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_take_ownership"):

        collector.add(
            Evidence(
                feature="Take Ownership Privilege",
                severity="HIGH",
                reason="SeTakeOwnershipPrivilege is enabled.",
                why="Allows ownership changes on protected objects."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_tcb_privilege"):

        collector.add(
            Evidence(
                feature="TCB Privilege",
                severity="CRITICAL",
                reason="SeTcbPrivilege detected.",
                why="This privilege is extremely powerful and rarely granted to ordinary processes."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_restore_privilege"):

        collector.add(
            Evidence(
                feature="Restore Privilege",
                severity="MEDIUM",
                reason="SeRestorePrivilege detected.",
                why="Allows restoration of protected files."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_load_driver_privilege"):

        collector.add(
            Evidence(
                feature="Load Driver Privilege",
                severity="CRITICAL",
                reason="SeLoadDriverPrivilege detected.",
                why="Allows loading kernel drivers and may enable kernel-level persistence.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    return collector

# ================================================================
# Netstat Rule Engine
# Matches extract_netstat()
# ================================================================

def analyze_netstat(netstat_features):

    collector = EvidenceCollector()

    if not netstat_features:
        return collector

    # ------------------------------------------------------------
    # Network Activity
    # ------------------------------------------------------------

    if get(netstat_features, "has_network_connection", False):

        collector.add(
            Evidence(
                feature="Network Activity",
                severity="INFO",
                reason="The process has active network connections.",
                why="Network communication is normal for many processes, but becomes significant when combined with other suspicious behaviors."
            )
        )

    # ------------------------------------------------------------

    conn_count = get(netstat_features, "connection_count", 0)

    if conn_count > 100:

        collector.add(
            Evidence(
                feature="High Connection Count",
                severity="MEDIUM",
                reason=f"{conn_count} active connections detected.",
                why="An unusually high number of network connections may indicate scanning, botnet activity, or malware."
            )
        )

    # ------------------------------------------------------------

    foreign = get(netstat_features, "foreign_ip_count", 0)

    if foreign > 0:

        collector.add(
            Evidence(
                feature="Foreign IP Communication",
                severity="MEDIUM",
                reason=f"Connections to {foreign} foreign IP address(es).",
                why="Communication with external IP addresses may represent command-and-control traffic.",
                mitre=MITRE["COMMAND_AND_CONTROL"]
            )
        )

    # ------------------------------------------------------------

    if get(netstat_features, "suspicious_port_flag", False):

        ports = get(netstat_features, "suspicious_ports_hit", [])

        collector.add(
            Evidence(
                feature="Suspicious Port Usage",
                severity="HIGH",
                reason=f"Observed ports: {', '.join(map(str, ports))}",
                why="Ports such as 4444, 1337, 9050, and similar are frequently associated with attacker tools.",
                mitre=MITRE["COMMAND_AND_CONTROL"]
            )
        )

    # ------------------------------------------------------------

    listeners = get(netstat_features, "ephemeral_listener_count", 0)

    if listeners > 0:

        collector.add(
            Evidence(
                feature="Ephemeral Listener",
                severity="MEDIUM",
                reason=f"{listeners} listener(s) on ephemeral ports.",
                why="Unexpected listeners on high-numbered ports may indicate backdoors."
            )
        )

    # ------------------------------------------------------------

    loopback = get(netstat_features, "loopback_connection_count", 0)

    if loopback > 20:

        collector.add(
            Evidence(
                feature="Heavy Loopback Communication",
                severity="LOW",
                reason=f"{loopback} loopback connections detected.",
                why="Large amounts of local IPC traffic may warrant investigation."
            )
        )

    # ------------------------------------------------------------

    dns = get(netstat_features, "dns_over_nonstandard_count", 0)

    if dns > 0:

        collector.add(
            Evidence(
                feature="Unexpected DNS Usage",
                severity="MEDIUM",
                reason=f"{dns} non-standard DNS connection(s).",
                why="DNS communication from unexpected processes can indicate tunneling or malware."
            )
        )

    return collector


# ================================================================
# Mutex Rule Engine
# Matches extract_mutex()
# ================================================================

def analyze_mutex(mutex_features):

    collector = EvidenceCollector()

    if not mutex_features:
        return collector

    mutexes = get(mutex_features, "mutexes", [])

    if not mutexes:
        return collector

    malware = []
    duplicate = []
    entropy_hits = []
    global_mutex = []
    guid = []

    seen = set()

    for mutex in mutexes:

        name = get(mutex, "mutex_name", "")

        # Known malware mutex
        if get(mutex, "known_malware_mutex", False):
            malware.append(name)

        # Duplicate mutex
        if name in seen:
            duplicate.append(name)
        seen.add(name)

        # High entropy
        e = get(mutex, "mutex_name_entropy", None)
        if e is not None and e > 4.5:
            entropy_hits.append(f"{name} ({e:.2f})")

        # Global namespace
        if name.startswith("Global\\"):
            global_mutex.append(name)

        # GUID-like mutex
        if get(mutex, "guid_like_mutex", False):
            guid.append(name)

    # ------------------------------------------------------------

    if malware:
        collector.add(
            Evidence(
                feature="Known Malware Mutex",
                severity="CRITICAL",
                reason=", ".join(malware[:5]),
                why="Mutex matches known malware indicators.",
                mitre=MITRE["DEFENSE_EVASION"]
            )
        )

    if duplicate:
        collector.add(
            Evidence(
                feature="Duplicate Mutex",
                severity="LOW",
                reason=f"{len(duplicate)} duplicate mutex names.",
                why="Duplicate mutex usage may indicate process coordination."
            )
        )

    if entropy_hits:
        collector.add(
            Evidence(
                feature="High Entropy Mutex",
                severity="MEDIUM",
                reason=", ".join(entropy_hits[:5]),
                why="Randomized mutex names are often used by malware."
            )
        )

    if global_mutex:
        collector.add(
            Evidence(
                feature="Global Mutex",
                severity="LOW",
                reason=", ".join(global_mutex[:5]),
                why="Global namespace mutexes allow cross-session synchronization."
            )
        )

    if guid:
        collector.add(
            Evidence(
                feature="GUID-like Mutex",
                severity="MEDIUM",
                reason=", ".join(guid[:5]),
                why="GUID-like mutex names are commonly used by malware to avoid collisions."
            )
        )

    return collector

# ================================================================
# Process Information Rule Engine
# Matches extract_procinfo()
# ================================================================

def analyze_procinfo(procinfo_features):

    collector = EvidenceCollector()

    if not procinfo_features:
        return collector

    if get(procinfo_features, "has_attached_debugger"):

        collector.add(
            Evidence(
                feature="Attached Debugger",
                severity="HIGH",
                reason="A debugger is attached to this process.",
                why="Debuggers are commonly used during malware execution or reverse engineering."
            )
        )

    if get(procinfo_features, "peb_dll_mismatch"):

        collector.add(
            Evidence(
                feature="PEB DLL Mismatch",
                severity="HIGH",
                reason="Loaded modules differ from the Process Environment Block.",
                why="PEB inconsistencies may indicate hidden or reflectively loaded modules.",
                mitre=MITRE["DEFENSE_EVASION"]
            )
        )

    if get(procinfo_features, "loading_from_temp_or_appdata"):

        collector.add(
            Evidence(
                feature="Executable in Temp/AppData",
                severity="HIGH",
                reason="Process image executed from Temp/AppData.",
                why="Legitimate system executables rarely execute from user-writable directories.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    if get(procinfo_features, "image_path_command_line_mismatch"):

        collector.add(
            Evidence(
                feature="Image Path Mismatch",
                severity="MEDIUM",
                reason="Image path differs from command line.",
                why="Attackers sometimes disguise executable locations."
            )
        )

    if get(procinfo_features, "aslr_disabled"):

        collector.add(
            Evidence(
                feature="ASLR Disabled",
                severity="MEDIUM",
                reason="Address Space Layout Randomization is disabled.",
                why="Disabling ASLR reduces exploit mitigation."
            )
        )

    if get(procinfo_features, "dep_disabled"):

        collector.add(
            Evidence(
                feature="DEP Disabled",
                severity="HIGH",
                reason="Data Execution Prevention is disabled.",
                why="DEP protects against code execution in writable memory."
            )
        )

    return collector


# ================================================================
# PSList Rule Engine
# Matches extract_pslist()
# ================================================================

def analyze_pslist(pslist_features):

    collector = EvidenceCollector()

    if not pslist_features:
        return collector

    if get(pslist_features, "parent_child_mismatch"):

        collector.add(
            Evidence(
                feature="Parent Process Mismatch",
                severity="HIGH",
                reason="Unexpected parent-child relationship detected.",
                why="Process lineage inconsistent with normal Windows behaviour."
            )
        )

    if get(pslist_features, "orphan_process_flag"):

        collector.add(
            Evidence(
                feature="Orphan Process",
                severity="MEDIUM",
                reason="Parent process is missing.",
                why="Orphan processes may result from process hollowing or terminated parents."
            )
        )

    if get(pslist_features, "commandline_empty"):

        collector.add(
            Evidence(
                feature="Empty Command Line",
                severity="LOW",
                reason="Process has an empty command line.",
                why="Legitimate applications usually retain command-line information."
            )
        )

    if get(pslist_features, "commandline_has_base64"):

        collector.add(
            Evidence(
                feature="Base64 Command Line",
                severity="HIGH",
                reason="Base64-encoded content detected in the command line.",
                why="PowerShell and malware frequently encode commands using Base64."
            )
        )

    if get(pslist_features, "commandline_has_url"):

        collector.add(
            Evidence(
                feature="URL in Command Line",
                severity="MEDIUM",
                reason="URL found in the command line.",
                why="Processes downloading payloads often contain URLs."
            )
        )

    entropy = get(pslist_features, "process_name_entropy")

    if entropy is not None and entropy > 3.5:

        collector.add(
            Evidence(
                feature="Random Process Name",
                severity="LOW",
                reason=f"Process name entropy = {entropy:.2f}.",
                why="Random-looking process names are common among malware."
            )
        )

    return collector


# ================================================================
# VAD Rule Engine
# Matches extract_vad()
# ================================================================

def analyze_vad(vad_features):

    collector = EvidenceCollector()

    if not vad_features:
        return collector

    rwx = get(vad_features, "private_rwx_region_count", 0)

    if rwx > 0:

        collector.add(
            Evidence(
                feature="Private RWX Memory",
                severity="CRITICAL",
                reason=f"{rwx} private RWX region(s) detected.",
                why="Private executable writable memory is a classic indicator of injected shellcode.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    no_file = get(vad_features, "no_file_backing_count", 0)

    if no_file > 5:

        collector.add(
            Evidence(
                feature="Anonymous Memory Regions",
                severity="MEDIUM",
                reason=f"{no_file} memory region(s) without file backing.",
                why="Anonymous executable memory may contain unpacked malware."
            )
        )

    return collector


# ================================================================
# Driver Rule Engine
# Matches global.driver_features
# ================================================================

def analyze_drivers(driver_features):

    collector = EvidenceCollector()

    if not driver_features:
        return collector

    unsigned = get(driver_features, "unsigned_driver_count", 0)

    if unsigned > 0:

        collector.add(
            Evidence(
                feature="Unsigned Driver",
                severity="CRITICAL",
                reason=f"{unsigned} unsigned driver(s) detected.",
                why="Unsigned kernel drivers are commonly associated with rootkits.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    hidden = get(driver_features, "hidden_driver_count", 0)

    if hidden > 0:

        collector.add(
            Evidence(
                feature="Hidden Driver",
                severity="CRITICAL",
                reason=f"{hidden} hidden driver(s) detected.",
                why="Hidden kernel drivers strongly indicate kernel-level stealth."
            )
        )

    rwx = get(driver_features, "rwx_driver_section_count", 0)

    if rwx > 0:

        collector.add(
            Evidence(
                feature="RWX Driver Section",
                severity="CRITICAL",
                reason=f"{rwx} driver(s) contain RWX sections.",
                why="Kernel drivers should rarely expose executable writable sections."
            )
        )

    return collector

# ================================================================
# Correlation Engine
# ================================================================

def correlate_findings(process_features,
                       thread_ev,
                       dll_ev,
                       handle_ev,
                       token_ev,
                       net_ev,
                       mutex_ev,
                       proc_ev,
                       ps_ev,
                       vad_ev,
                       driver_ev):

    collector = EvidenceCollector()

    tf = process_features.get("thread_features", {})
    df = process_features.get("dll_features", {})
    hf = process_features.get("handle_features", {})
    inf = process_features.get("impersonation_features", {})
    nf = process_features.get("netstat_features", {})
    pf = process_features.get("procinfo_features", {})
    vf = process_features.get("vad_features", {})

    # ============================================================
    # PROCESS INJECTION
    # ============================================================

    injection_score = 0

    if get(tf, "remote_thread_flag"):
        injection_score += 2

    if get(vf, "private_rwx_region_count", 0) > 0:
        injection_score += 2

    if get(tf, "thread_start_address_anomaly_count", 0) > 0:
        injection_score += 1

    if get(pf, "peb_dll_mismatch"):
        injection_score += 1

    if injection_score >= 4:

        collector.add(
            Evidence(
                feature="Process Injection",
                severity="CRITICAL",
                reason="Multiple indicators strongly suggest process injection.",
                why="Remote threads, RWX memory and abnormal thread execution commonly occur together during code injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ============================================================
    # REFLECTIVE DLL LOADING
    # ============================================================

    reflective = False

    for dll in get(df, "dlls", []):

        if get(dll, "missing_from_peb_reflective_indicator"):

            reflective = True
            break

    if reflective and get(vf, "private_rwx_region_count", 0) > 0:

        collector.add(
            Evidence(
                feature="Reflective DLL Injection",
                severity="CRITICAL",
                reason="DLL missing from PEB together with private executable memory.",
                why="Reflective DLL loading bypasses the Windows loader and commonly leaves these artifacts.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ============================================================
    # CREDENTIAL DUMPING
    # ============================================================

    cred_score = 0

    if get(hf, "open_lsass_handle"):
        cred_score += 2

    if get(inf, "has_debug_privilege"):
        cred_score += 2

    if get(hf, "sensitive_registry_files_count", 0) > 0:
        cred_score += 1

    if cred_score >= 3:

        collector.add(
            Evidence(
                feature="Credential Dumping",
                severity="CRITICAL",
                reason="Multiple indicators of credential theft detected.",
                why="LSASS access combined with elevated privileges strongly suggests credential dumping.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ============================================================
    # COMMAND AND CONTROL
    # ============================================================

    c2_score = 0

    if get(nf, "foreign_ip_count", 0) > 0:
        c2_score += 1

    if get(nf, "suspicious_port_flag"):
        c2_score += 2

    if get(nf, "ephemeral_listener_count", 0) > 0:
        c2_score += 1

    if c2_score >= 3:

        collector.add(
            Evidence(
                feature="Possible Command and Control",
                severity="HIGH",
                reason="Suspicious external communication detected.",
                why="Unexpected foreign IPs and suspicious ports frequently indicate C2 activity.",
                mitre=MITRE["COMMAND_AND_CONTROL"]
            )
        )

    # ============================================================
    # PRIVILEGE ESCALATION
    # ============================================================

    escalation = 0

    if get(inf, "token_duplication"):
        escalation += 1

    if get(inf, "sid_mismatch"):
        escalation += 1

    if get(inf, "has_tcb_privilege"):
        escalation += 2

    if get(inf, "has_take_ownership"):
        escalation += 1

    if escalation >= 3:

        collector.add(
            Evidence(
                feature="Privilege Escalation",
                severity="HIGH",
                reason="Multiple token manipulation indicators detected.",
                why="Privilege escalation often involves duplicated tokens, SID changes and powerful privileges."
            )
        )

    # ============================================================
    # KERNEL ROOTKIT
    # ============================================================

    drv = process_features.get("global_driver_features", {})

    if drv:

        if (
            get(drv, "hidden_driver_count", 0) > 0 and
            get(drv, "unsigned_driver_count", 0) > 0
        ):

            collector.add(
                Evidence(
                    feature="Kernel Rootkit",
                    severity="CRITICAL",
                    reason="Hidden unsigned kernel driver detected.",
                    why="Kernel rootkits commonly hide unsigned drivers to evade detection.",
                    mitre=MITRE["PERSISTENCE"]
                )
            )

    return collector

# ================================================================
# Build Final Process Report
# ================================================================

def build_process_report(pid, process_features, global_driver_features):

    thread_ev = analyze_threads(
        process_features.get("thread_features", {})
    )

    dll_ev = analyze_dlls(
        process_features.get("dll_features", {})
    )

    handle_ev = analyze_handles(
        process_features.get("handle_features", {})
    )

    token_ev = analyze_tokens(
        process_features.get("impersonation_features", {})
    )

    net_ev = analyze_netstat(
        process_features.get("netstat_features", {})
    )

    mutex_ev = analyze_mutex(
        process_features.get("mutex_features", {})
    )

    proc_ev = analyze_procinfo(
        process_features.get("procinfo_features", {})
    )

    ps_ev = analyze_pslist(
        process_features.get("pslist_features", {})
    )

    vad_ev = analyze_vad(
        process_features.get("vad_features", {})
    )

    driver_ev = analyze_drivers(
        global_driver_features
    )

    process_features["global_driver_features"] = global_driver_features

    corr_ev = correlate_findings(
        process_features,
        thread_ev,
        dll_ev,
        handle_ev,
        token_ev,
        net_ev,
        mutex_ev,
        proc_ev,
        ps_ev,
        vad_ev,
        driver_ev
    )

    final = EvidenceCollector()

    for ev in [
        thread_ev,
        dll_ev,
        handle_ev,
        token_ev,
        net_ev,
        mutex_ev,
        proc_ev,
        ps_ev,
        vad_ev,
        driver_ev,
        corr_ev
    ]:
        final.extend(ev.items)

    final.deduplicate()

    return final

# ================================================================
# Analyst Summary
# ================================================================

def generate_summary(process_name, collector):

    score = collector.score()

    risk = collector.risk()

    features = [
        e.feature
        for e in collector.items[:5]
    ]

    if not features:

        return (
            f"{process_name} exhibited no significant malicious indicators."
        )

    feature_text = ", ".join(features)

    return (
        f"{process_name} generated "
        f"{len(collector.items)} evidence item(s). "
        f"Overall risk is {risk}. "
        f"Key observations include {feature_text}. "
        f"Total detection score: {score}."
    )

# ================================================================
# Convert Collector -> JSON
# ================================================================

def collector_to_json(
    pid,
    process_name,
    collector
):

    return {

        "pid": pid,

        "process_name": process_name,

        "risk": collector.risk(),

        "confidence": collector.confidence(),

        "score": collector.score(),

        "evidence_count": len(
            collector.items
        ),

        "summary": generate_summary(
            process_name,
            collector
        ),

        "evidence": [

            item.to_dict()

            for item in collector.items

        ]

    }

# ================================================================
# Build evidence.json
# ================================================================

def build_evidence(features_json):

    output = {

        "processes": {}

    }

    global_driver_features = (
        features_json
        .get("global", {})
        .get("driver_features", {})
    )

    for pid, proc in features_json["processes"].items():

        process_name = pid

        collector = build_process_report(
            pid,
            proc,
            global_driver_features
        )

        output["processes"][pid] = (
            collector_to_json(
                pid,
                process_name,
                collector
            )
        )

    return output


def evidence_report(features_json, out_path, label=""):
    """
    Takes a features dict (as returned in-memory by extract_features()
    above -- either PRE or DURING) DIRECTLY, runs it through the rule
    engines + correlation engine, and writes the resulting evidence.json.
    No re-read of pre_features.json / during_features.json from disk
    required.
    """
    prefix = f"[{label}] " if label else ""
    print(f"{prefix}[+] Building evidence report...")

    output = build_evidence(features_json)

    Path(out_path).write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")

    print(f"{prefix}[OK] Wrote evidence report -> {out_path}")

    return output


# =============================================================================
# ==========================  STAGE 6: THREAT INTEL  ==========================
# (from threat_intel_pipeline.py -- logic unchanged)
# =============================================================================

# ---------------- CONFIG ---------------- #

# Load API keys from environment variables (do NOT hardcode keys in source).
#   PowerShell: $env:VT_API_KEY="your_key_here"
#   PowerShell: $env:MB_AUTH_KEY="your_key_here"   # get one free at https://auth.abuse.ch/
VT_API_KEY = os.environ.get("VT_API_KEY", "")
MB_AUTH_KEY = os.environ.get("MB_AUTH_KEY", "")

TI_MAX_IOCS = 20            # cap to respect API rate limits
TI_API_DELAY_SECONDS = 15   # VT public API: 4 req/min -> be conservative

# ---------------- STEP 1: EXTRACTION - PCAP ---------------- #

def extract_from_pcap(pcap_file):
    """Pull IPs and DNS query domains out of a pcap."""
    if not os.path.exists(pcap_file):
        print(f"[!] PCAP not found, skipping: {pcap_file}")
        return set()

    packets = rdpcap(pcap_file)
    iocs = set()

    for pkt in packets:
        if IP in pkt:
            iocs.add(pkt[IP].src)
            iocs.add(pkt[IP].dst)

        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode().strip(".")
                if qname:
                    iocs.add(qname)
            except Exception:
                pass

    print(f"[+] PCAP: extracted {len(iocs)} raw IoCs")
    return iocs


# ---------------- STEP 2: EXTRACTION - SYSMON CSV ---------------- #

def extract_from_sysmon(csv_file):
    """Pull IPs, domains, hashes, and process image paths from Sysmon CSV."""
    if not os.path.exists(csv_file):
        print(f"[!] Sysmon CSV not found, skipping: {csv_file}")
        return set()

    df = pd.read_csv(csv_file)
    iocs = set()

    for _, row in df.iterrows():
        if pd.notna(row.get("SourceIp")):
            iocs.add(str(row["SourceIp"]))
        if pd.notna(row.get("DestinationIp")):
            iocs.add(str(row["DestinationIp"]))
        if pd.notna(row.get("QueryName")):
            iocs.add(str(row["QueryName"]))

        if pd.notna(row.get("Hashes")):
            for h in re.findall(r"[A-Fa-f0-9]{32,64}", str(row["Hashes"])):
                iocs.add(h)

        if pd.notna(row.get("Image")):
            iocs.add(str(row["Image"]))

    print(f"[+] Sysmon CSV: extracted {len(iocs)} raw IoCs")
    return iocs


# ---------------- STEP 3: SHARED FILTER / CLEAN ---------------- #

TI_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
TI_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")
TI_EMPTY_HASH = "00000000000000000000000000000000"


def filter_iocs(raw_iocs, max_iocs=TI_MAX_IOCS):
    """Keep only valid, non-noise IoCs (IP / domain / hash), capped and deduped."""
    filtered = []

    for ioc in raw_iocs:
        ioc = str(ioc).strip()

        if len(ioc) < 3:
            continue
        if "\\" in ioc:                      # Windows file paths / process images
            continue
        if "local" in ioc.lower():           # internal / .local domains
            continue
        if ioc.startswith("_"):              # service DNS records (e.g. _ldap._tcp)
            continue
        if "wpad" in ioc.lower():
            continue
        if ioc == TI_EMPTY_HASH:
            continue

        if TI_IP_RE.match(ioc):
            filtered.append(ioc)
        elif TI_HASH_RE.match(ioc):
            filtered.append(ioc)
        elif "." in ioc and not ioc.lower().endswith(".local"):
            filtered.append(ioc)

    filtered = list(dict.fromkeys(filtered))[:max_iocs]  # dedupe, preserve order, cap
    print(f"[+] Filtered down to {len(filtered)} valid IoCs (max {max_iocs})")
    return filtered


def classify_ioc(ioc):
    if TI_HASH_RE.match(ioc):
        return "hash"
    if TI_IP_RE.match(ioc):
        return "ip"
    if "." in ioc:
        return "domain"
    return "other"


# ---------------- STEP 4: ENRICHMENT SOURCES ---------------- #

def query_virustotal(ioc, ioc_type):
    if not VT_API_KEY:
        return {"source": "VirusTotal", "error": "No VT_API_KEY configured"}

    headers = {"x-apikey": VT_API_KEY}
    endpoint_map = {
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
    }
    url = endpoint_map.get(ioc_type)
    if not url:
        return {"source": "VirusTotal", "error": f"Unsupported type: {ioc_type}"}

    try:
        r = requests.get(url, headers=headers, timeout=30)

        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
            }
        elif r.status_code == 404:
            return {"source": "VirusTotal", "info": "No data found"}
        elif r.status_code == 401:
            return {"source": "VirusTotal", "error": "Invalid API key"}
        elif r.status_code == 429:
            return {"source": "VirusTotal", "error": "Rate limit exceeded"}
        else:
            return {"source": "VirusTotal", "error": f"HTTP {r.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def query_malwarebazaar(file_hash):
    if not MB_AUTH_KEY:
        return {"source": "MalwareBazaar", "error": "No MB_AUTH_KEY configured (get one free at https://auth.abuse.ch/)"}

    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": MB_AUTH_KEY}
    payload = {"query": "get_info", "hash": file_hash}

    try:
        r = requests.post(url, data=payload, headers=headers, timeout=30)
        if r.status_code == 200:
            res = r.json()
            if res.get("query_status") == "ok" and res.get("data"):
                sample = res["data"][0]
                return {
                    "source": "MalwareBazaar",
                    "malware_family": sample.get("signature"),
                    "file_type": sample.get("file_type"),
                }
            return {"source": "MalwareBazaar", "info": "No data found"}
        elif r.status_code == 401:
            return {"source": "MalwareBazaar", "error": "Invalid or missing Auth-Key"}
        return {"source": "MalwareBazaar", "error": f"HTTP {r.status_code}"}

    except Exception as e:
        return {"source": "MalwareBazaar", "error": str(e)}


# ---------------- STEP 5: ENRICHMENT ENGINE ---------------- #

def enrich_iocs(iocs, delay=TI_API_DELAY_SECONDS):
    enriched_results = []

    for i, ioc in enumerate(iocs, 1):
        ioc_type = classify_ioc(ioc)
        result = {"ioc": ioc, "type": ioc_type, "enrichment": []}

        vt = query_virustotal(ioc, ioc_type)
        if vt:
            result["enrichment"].append(vt)

        if ioc_type == "hash":
            result["enrichment"].append(query_malwarebazaar(ioc))

        enriched_results.append(result)
        print(f"    [{i}/{len(iocs)}] {ioc_type:6s} {ioc}")

        if i < len(iocs):
            time.sleep(delay)

    return enriched_results


# ---------------- STEP 6: SAVE HELPERS ---------------- #

def save_json_ti(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[OK] Saved: {path}")


def run_threat_intel(pcap_path, sysmon_path, extracted_out, intel_out,
                      max_iocs=TI_MAX_IOCS, delay=TI_API_DELAY_SECONDS):
    """
    Runs the standalone threat_intel_pipeline.py's full flow (extract ->
    filter -> save -> enrich -> save), unchanged, just callable from the
    unified main() instead of its own __main__ block.
    """
    print("=" * 60)
    print("THREAT INTELLIGENCE PIPELINE")
    print("=" * 60)

    # --- Extract ---
    pcap_iocs = extract_from_pcap(pcap_path) if pcap_path else set()
    sysmon_iocs = extract_from_sysmon(sysmon_path) if sysmon_path else set()
    raw_iocs = pcap_iocs | sysmon_iocs
    print(f"[+] Combined raw IoCs (pre-filter): {len(raw_iocs)}")

    # --- Filter / clean ---
    filtered_iocs = filter_iocs(raw_iocs, max_iocs=max_iocs)

    # --- Output 1: extracted IoCs ---
    save_json_ti({"iocs": filtered_iocs}, extracted_out)

    # --- Enrich ---
    print("[*] Querying VirusTotal / MalwareBazaar...")
    enriched = enrich_iocs(filtered_iocs, delay=delay)

    # --- Output 2: enriched threat intel ---
    save_json_ti(enriched, intel_out)

    print("=" * 60)
    print("DONE")
    print("=" * 60)

    return filtered_iocs, enriched


# =============================================================================
# ====================  STAGE 7: HOST COMPROMISE ASSESSMENT  ==================
# (from the two host-assessment notebook modules -- logic unchanged)
# =============================================================================

# -----------------------------------------------------------------------
# STAGE 7a: FUSION SCORE (threat intel + anomaly z-scores combined)
# -----------------------------------------------------------------------

def load_json_fusion(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def normalize_anomaly(anomaly_results):
    """
    Convert raw z-score sum into 0-100 scale
    """
    if not anomaly_results:
        return 0

    scores = [r["score"] for r in anomaly_results]

    max_score = max(scores)
    if max_score == 0:
        return 0

    # Take top suspicious process
    top_score = scores[0]

    normalized = (top_score / max_score) * 100
    return normalized


def compute_threat_score(threat_data):
    total = 0

    for ioc in threat_data:

        for entry in ioc["enrichment"]:
            source = entry.get("source")

            if source == "VirusTotal":
                malicious = entry.get("malicious", 0)
                suspicious = entry.get("suspicious", 0)

                if malicious >= 10:
                    total += 40
                elif malicious >= 5:
                    total += 25

                if suspicious >= 5:
                    total += 10

            elif source == "AbuseIPDB":
                abuse = entry.get("abuse_score", 0)

                if abuse >= 80:
                    total += 30
                elif abuse >= 50:
                    total += 20
                elif abuse >= 20:
                    total += 10

            elif source == "MalwareBazaar":
                if entry.get("malware_family"):
                    total += 35

    return total


def combined_assessment(threat_data, anomaly_results):

    threat_score = compute_threat_score(threat_data)
    anomaly_score = normalize_anomaly(anomaly_results)

    # WEIGHTS (tunable)
    W_THREAT = 0.6
    W_ANOMALY = 0.4

    final_score = (threat_score * W_THREAT) + (anomaly_score * W_ANOMALY)

    # ==================================
    # FINAL VERDICT
    # ==================================
    if final_score >= 70:
        verdict = "COMPROMISED"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "threat_score": threat_score,
        "anomaly_score": anomaly_score,
        "final_score": final_score,
        "verdict": verdict
    }


def run_fusion_score(threat_file, anomaly_file, output_file):
    """
    Runs the standalone "final fusion score" notebook module's flow
    (load threat + anomaly data -> combined_assessment -> save), unchanged,
    just callable from the unified main() with CLI-supplied paths instead
    of the original hardcoded Colab paths.
    """
    print("[+] Loading data...")
    threat_data = load_json_fusion(threat_file)
    anomaly_data = load_json_fusion(anomaly_file)

    print("[+] Running combined scoring...")
    result = combined_assessment(threat_data, anomaly_data)

    Path(output_file).write_text(json.dumps(result, indent=4), encoding="utf-8")

    print("\nFINAL HOST ASSESSMENT")
    print(f"Threat Score   : {result['threat_score']}")
    print(f"Anomaly Score  : {result['anomaly_score']:.2f}")
    print(f"Final Score    : {result['final_score']:.2f}")
    print(f"Verdict        : {result['verdict']}")

    print(f"\n[OK] Saved to: {output_file}")

    return result


# -----------------------------------------------------------------------
# STAGE 7b: HOST COMPROMISE ASSESSMENT (threat intel only)
# -----------------------------------------------------------------------

def load_data(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def score_ioc(ioc_data):

    score = 0

    for entry in ioc_data["enrichment"]:

        source = entry.get("source")

        # ------------------------
        # VirusTotal
        # ------------------------
        if source == "VirusTotal":

            malicious = entry.get("malicious", 0)
            suspicious = entry.get("suspicious", 0)

            if malicious >= 10:
                score += 40
            elif malicious >= 5:
                score += 25

            if suspicious >= 5:
                score += 10

        # ------------------------
        # AbuseIPDB
        # ------------------------
        elif source == "AbuseIPDB":

            abuse_score = entry.get("abuse_score", 0)

            if abuse_score >= 80:
                score += 30
            elif abuse_score >= 50:
                score += 20
            elif abuse_score >= 20:
                score += 10

        # ------------------------
        # MalwareBazaar
        # ------------------------
        elif source == "MalwareBazaar":

            if entry.get("malware_family"):
                score += 35

    return score


def assess_host(enriched_data):

    total_score = 0
    detailed_results = []

    for ioc in enriched_data:

        ioc_score = score_ioc(ioc)
        total_score += ioc_score

        detailed_results.append({
            "ioc": ioc["ioc"],
            "type": ioc["type"],
            "score": ioc_score
        })

    # ------------------------
    # FINAL VERDICT
    # ------------------------
    if total_score >= 70:
        verdict = "COMPROMISED"
    elif total_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "total_score": total_score,
        "verdict": verdict,
        "details": detailed_results
    }


def save_output(data, file_path):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


def run_host_assessment(input_file, output_file):
    """
    Runs the standalone "host compromise assessment" notebook module's flow
    (load enriched threat intel -> assess_host -> save), unchanged, just
    wrapped into a callable with CLI-supplied paths instead of the original
    module-level INPUT_FILE/OUTPUT_FILE constants.
    """
    data = load_data(input_file)

    result = assess_host(data)

    save_output(result, output_file)

    print("Host Compromise Assessment Completed")
    print(f"Total Score: {result['total_score']}")
    print(f"Verdict: {result['verdict']}")

    return result


# =============================================================================
# =====================  STAGE 8: LLM REASONING ENGINE  =======================
# (from Module 13 -- LLM Reasoning Engine notebook script -- logic unchanged)
# =============================================================================
#
# Final analytical stage before report generation. Takes the outputs of
# every upstream module -- correlated evidence, baseline deviations, threat
# intelligence, and the fused host-compromise score -- and asks an LLM
# (Google Gemini) to reason over all of it and produce an analyst-grade
# narrative (attack_narrative, what_happened, why, recommendations,
# attribution, etc).
#
# NOTE: the `google-genai` import is kept lazy (done inside run_llm_module()
# below, at the same spot the original script's own import-guard sat) so the
# rest of the unified pipeline (stages 1-7) doesn't require this dependency
# to be installed -- only running STAGE 8 does. The import-guard's own
# behavior (print + sys.exit(1) if missing) is unchanged from the original.

# ---- Module 13 CONFIG (unchanged) ----
LLM_MODEL = "gemini-3.5-flash"   # swap for a "pro"-tier Gemini model if you want deeper reasoning over speed/cost
LLM_MAX_TOKENS = 12000           # raised from 4000 -- large incidents were getting truncated mid-JSON

# Caps on how much upstream data gets sent to the model per run.
# Keeps the prompt (and therefore the required output) within budget
# even on very large incidents. Raise/lower as needed.
MAX_TIMELINE_EVENTS = 150
MAX_EVIDENCE_PROCESSES = 30
MAX_BASELINE_PROCESSES = 30

# Sensible fallbacks matching the original script's hardcoded Colab paths.
DEFAULT_LLM_EVIDENCE_FILE = "/content/drive/MyDrive/dataset/Asynrat/evidence.json"
DEFAULT_LLM_PRE_EVIDENCE_FILE = "/content/drive/MyDrive/dataset/Asynrat/preevidence.json"
DEFAULT_LLM_BASELINE_FILE = "/content/drive/MyDrive/dataset/Asynrat/baseline_comparison.json"
DEFAULT_LLM_THREAT_INTEL_FILE = "/content/drive/MyDrive/dataset/Asynrat/threat_intel_output.json"
DEFAULT_LLM_HOST_SCORE_FILE = "/content/drive/MyDrive/dataset/Asynrat/final_fusion_score.json"
DEFAULT_LLM_OUTPUT_FILE = "/content/drive/MyDrive/dataset/llm_reasoning_output.json"


def load_json_llm(path, default=None):
    """Load a JSON file, tolerating missing upstream modules."""
    p = Path(path)
    if not p.exists():
        print(f"[!] Not found, skipping: {path}")
        return default if default is not None else {}
    return json.loads(p.read_text(encoding="utf-8"))


def build_timeline(evidence_data):
    """
    Flattens per-process evidence into a chronologically-agnostic,
    severity-ordered timeline of events. Real timestamps (if present
    on evidence items) are used when available; otherwise events are
    ordered by severity so the most significant activity leads.
    """

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    events = []

    processes = evidence_data.get("processes", evidence_data)

    if not isinstance(processes, dict):
        return events

    for pid, proc in processes.items():
        process_name = proc.get("process_name", pid)

        for item in proc.get("evidence", []):
            events.append({
                "pid": pid,
                "process": process_name,
                "feature": item.get("feature"),
                "severity": item.get("severity", "INFO"),
                "reason": item.get("reason"),
                "mitre": item.get("mitre"),
                "timestamp": item.get("timestamp"),  # may be None
            })

    events.sort(key=lambda e: (
        e["timestamp"] is None,
        e["timestamp"] or "",
        severity_rank.get(e["severity"], 5),
    ))

    return events


def build_evidence_graph(evidence_data):
    """
    Summarizes evidence.json into a compact per-process graph node:
    risk, confidence, score, and top evidence -- so the prompt stays
    within a reasonable token budget even on large incidents.
    """

    processes = evidence_data.get("processes", evidence_data)

    graph = []

    if not isinstance(processes, dict):
        return graph

    for pid, proc in processes.items():
        graph.append({
            "pid": pid,
            "process_name": proc.get("process_name", pid),
            "risk": proc.get("risk") or proc.get("risk_level"),
            "confidence": proc.get("confidence"),
            "score": proc.get("score") or proc.get("risk_score"),
            "top_evidence": [
                {
                    "feature": e.get("feature"),
                    "severity": e.get("severity"),
                    "mitre": e.get("mitre"),
                }
                for e in proc.get("evidence", [])[:8]
            ],
        })

    # Most suspicious processes first
    graph.sort(key=lambda g: g.get("score") or 0, reverse=True)

    return graph


def summarize_threat_intel(threat_data):
    if not threat_data:
        return []

    summary = []
    for ioc in threat_data if isinstance(threat_data, list) else threat_data.get("iocs", []):
        entry = {
            "ioc": ioc.get("ioc"),
            "type": ioc.get("type"),
            "enrichment": [],
        }
        for e in ioc.get("enrichment", []):
            entry["enrichment"].append({
                "source": e.get("source"),
                "malicious": e.get("malicious"),
                "abuse_score": e.get("abuse_score"),
                "malware_family": e.get("malware_family"),
                "reputation": e.get("reputation"),
            })
        summary.append(entry)

    return summary


LLM_SYSTEM_PROMPT = """You are the LLM Reasoning Engine stage of an automated memory-forensics
pipeline (Sysmon-triggered, Volatility/Velociraptor-based). You receive
already-computed, structured outputs from upstream modules: a
severity-ordered timeline, a per-process evidence graph for the
incident ("during") snapshot, an optional evidence graph for the
pre-incident ("baseline") snapshot of the same host, threat-intel
enrichment for observed IoCs, and a fused host-compromise score.

Your job is NOT to re-detect anomalies -- that has already happened.
Your job is to reason over what has already been detected, connect it
into a coherent story, and produce an analyst-grade explanation that a
Tier-2/Tier-3 SOC analyst could act on without re-reading raw logs.

REASONING APPROACH (do this before you write the final JSON):
1. Establish the kill-chain / attack-lifecycle position of each notable
   process (initial access, execution, persistence, privilege
   escalation, defense evasion, credential access, discovery, lateral
   movement, collection, C2, exfiltration, impact). Use MITRE ATT&CK
   tactic/technique IDs already present in the evidence where possible;
   do not fabricate IDs that aren't supported by the data or well-known
   technique definitions.
2. Build the causal chain between processes: which process likely
   spawned, injected into, or handed off to which other process/PID,
   and in what order, using timestamps where present and severity/logic
   otherwise.
3. Cross-reference the incident evidence graph against the baseline
   evidence graph (if provided): flag anything NEW, ESCALATED (higher
   severity/score than at baseline), or MISSING-BUT-EXPECTED. Treat
   baseline-consistent, unescalated evidence as low-signal noise rather
   than an indicator of compromise.
4. Cross-reference threat intelligence: tie any malicious/verified IOC
   directly to the specific process/PID or evidence item it came from,
   and note reputation/abuse scores or malware family attributions
   supplied. If an IOC is present but enrichment is inconclusive or
   benign, say so rather than treating its mere presence as malicious.
5. Weigh the fused host-compromise score against your own read of the
   evidence. If your narrative and the host score disagree, call that
   out explicitly and explain the discrepancy instead of silently
   picking one.
6. Actively consider alternative, benign explanations (admin tooling,
   software updates, backup jobs, known-noisy EDR/AV behavior) before
   settling on a malicious interpretation, and note when evidence is
   too sparse/ambiguous to distinguish between them.

When a baseline evidence graph is provided, use it as ground truth for
"normal" on this host: evidence/processes that also appear in the
baseline are less significant on their own, while evidence that is new
in the incident snapshot (or has escalated in severity/score versus
baseline) should be weighted more heavily and called out explicitly.
If no baseline evidence graph is provided (empty list), reason from the
incident evidence graph alone and say so.

IMPORTANT LENGTH CONSTRAINT: Be concise but information-dense. Every
sentence should carry a specific fact (a PID, process name, technique
ID, IOC, or score) rather than generic filler. "attack_narrative"
should be at most 6-8 sentences and should read as a chronological
story with named actors (processes/PIDs). "what_happened" should be at
most 4-5 sentences of confirmed, evidence-grounded observations only
(no speculation). "why" should be at most 5-6 sentences explaining the
reasoning chain from evidence to verdict. Recommendations should be
short, specific, prioritized, actionable bullet-style strings (one
sentence each, ideally naming the specific PID/process/IOC/host
artifact to act on), no more than 6-8 of them, ordered from most to
least urgent. This is a fixed-size JSON report field, not a full
incident report -- prioritize the most important, highest-confidence,
most specific points over exhaustive or generic detail.

Respond with ONLY a single JSON object (no markdown fences, no prose
outside the JSON) with exactly these keys:

{
  "attack_narrative": "<a chronological, plain-English narrative of how the incident likely unfolded, referencing specific processes/PIDs, techniques, and (if present) IOCs/timestamps, in the order events likely occurred>",
  "what_happened": "<concise factual summary of the confirmed observations, grounded only in the provided data>",
  "why": "<explanation of why these observations indicate compromise (or don't), reasoning explicitly from evidence to conclusion, including how baseline comparison and threat intel influenced the verdict>",
  "key_evidence": [
    {
      "pid": "<pid or null>",
      "process": "<process name or null>",
      "signal": "<the specific feature/technique/IOC that matters>",
      "significance": "<one sentence on why this specific item is the strongest support for the verdict>",
      "new_or_baseline": "new|escalated|baseline_consistent|unknown"
    }
  ],
  "severity_assessment": {
    "overall_verdict": "Benign|Suspicious|Likely Compromised|Confirmed Compromised",
    "host_score_agreement": "agrees|disagrees|partial",
    "rationale": "<1-2 sentences reconciling your verdict with the fused host-compromise score>"
  },
  "alternative_explanations": "<1-3 sentences on plausible benign explanations you considered and why you ruled them in/out, or 'None considered plausible given the evidence' if truly none>",
  "recommendations": ["<action item 1, ideally naming a specific PID/process/host artifact>", "<action item 2>", "..."],
  "attribution": {
    "likely_technique_ids": ["T####", "..."],
    "kill_chain_stages": ["<e.g. Initial Access, Execution, Persistence, ...>"],
    "possible_actor_or_family": "<name if threat intel supports it, else 'Unknown'>",
    "confidence": "Low|Medium|High",
    "rationale": "<1-3 sentences tying attribution back to specific evidence, IOCs, or technique IDs actually present in the input>"
  }
}

Rules:
- Ground every claim in the provided data. Do not invent PIDs, IPs, hashes, technique IDs, or timestamps not present in (or directly inferable from) the input.
- If evidence is weak, sparse, or contradictory, say so explicitly in "why" and "alternative_explanations", and lower your confidence rather than overstating certainty.
- If the host score / verdict indicates the host is clean, "attack_narrative", "severity_assessment", and "attribution" should reflect that plainly rather than manufacturing an incident.
- Distinguish evidence that is new/escalated versus baseline from evidence that was already present at baseline; do not treat baseline-consistent findings as strong indicators of compromise.
- Prefer specificity over hedging: name the PID/process/IOC responsible for each claim rather than referring to "some processes" or "certain activity."
- Keep the JSON valid and parseable. Always finish the JSON object completely -- never truncate mid-field. If you are close to the token limit, shorten prose fields (not by dropping keys) so the JSON still closes cleanly.
"""


def build_user_prompt(timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score):
    payload = {
        "timeline": timeline,
        "evidence_graph": evidence_graph,
        "baseline_evidence_graph": baseline_evidence_graph,
        "threat_intelligence": threat_intel,
        "host_score": host_score,
    }
    return (
        "Here is the structured forensic data for this incident.\n\n"
        "SECTION GUIDE:\n"
        "- timeline: severity/time-ordered list of individual evidence events "
        "across all processes (fields: pid, process, feature, severity, reason, mitre, timestamp).\n"
        "- evidence_graph: per-process summary for the INCIDENT snapshot, sorted "
        "most-suspicious first (fields: pid, process_name, risk, confidence, score, top_evidence).\n"
        "- baseline_evidence_graph: same shape as evidence_graph but for the "
        "PRE-INCIDENT snapshot of this host -- use it to tell new/escalated "
        "activity apart from pre-existing, presumably benign activity. Empty "
        "list means no baseline was available.\n"
        "- threat_intelligence: enrichment for observed IOCs (fields: ioc, type, "
        "enrichment[].source/malicious/abuse_score/malware_family/reputation).\n"
        "- host_score: the fused host-compromise score/verdict from the upstream "
        "scoring module (and baseline_deviations if present), to be reconciled "
        "with your own read of the evidence in severity_assessment.\n\n"
        "DATA:\n"
        + json.dumps(payload, indent=2, default=str)
        + "\n\nProduce the JSON object described in your instructions."
    )


def run_llm_reasoning(client, timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score):
    user_prompt = build_user_prompt(timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score)

    response = client.models.generate_content(
        model=LLM_MODEL,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=LLM_SYSTEM_PROMPT,
            max_output_tokens=LLM_MAX_TOKENS,
            response_mime_type="application/json",
        ),
    )

    # Diagnostic: log why generation stopped. If this prints something
    # other than STOP (e.g. MAX_TOKENS), the response was cut off and
    # you need to raise MAX_TOKENS and/or trim the input further.
    try:
        finish_reason = response.candidates[0].finish_reason
        print(f"[debug] finish_reason: {finish_reason}")
    except Exception:
        pass

    text = (response.text or "").strip()
    print(f"[debug] response length: {len(text)} chars")

    # Strip accidental markdown fences, just in case
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"[!] Model did not return valid JSON. Error: {e}")
        return {
            "attack_narrative": None,
            "what_happened": None,
            "why": None,
            "recommendations": [],
            "attribution": None,
            "raw_response": text,
        }


def run_llm_module(evidence_file, pre_evidence_file, baseline_file,
                    threat_intel_file, host_score_file, output_file):
    """
    Runs the standalone Module 13 script's main() flow, unchanged, just
    wrapped into a callable with CLI-supplied paths instead of the
    original hardcoded Colab paths. The google-genai import-guard is kept
    exactly as written, just moved here so it only fires when STAGE 8 is
    actually invoked (not at import time for the whole unified pipeline).
    """
    global genai, types
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        print("[!] Missing dependency. Install it with:")
        print("    pip install google-genai")
        sys.exit(1)

    # Get GEMINI_API_KEY directly from environment just before use
    api_key = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6KFwnB9mn19NtaT-6OcUOsHmp8cJyzkU9O9DDkJrSUXDg")

    if not api_key:
        print("[!] GEMINI_API_KEY is not set. Set it with:")
        print("    export GEMINI_API_KEY=AIza...")
        print("    (or, in Colab: os.environ['GEMINI_API_KEY'] = '...')")
        print("    Get a key at https://aistudio.google.com/apikey")
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    print("[+] Loading upstream module outputs...")
    evidence_data = load_json_llm(evidence_file, default={})
    pre_evidence_data = load_json_llm(pre_evidence_file, default={})
    baseline_data = load_json_llm(baseline_file, default={})
    threat_data = load_json_llm(threat_intel_file, default=[])
    host_score = load_json_llm(host_score_file, default={})

    print("[+] Building timeline from correlated evidence...")
    timeline = build_timeline(evidence_data)

    print("[+] Building incident evidence graph...")
    evidence_graph = build_evidence_graph(evidence_data)

    print("[+] Building baseline (pre_evidence) evidence graph...")
    baseline_evidence_graph = build_evidence_graph(pre_evidence_data) if pre_evidence_data else []

    print("[+] Summarizing threat intelligence...")
    threat_intel = summarize_threat_intel(threat_data)

    if baseline_data:
        host_score = {**host_score, "baseline_deviations": baseline_data}

    # --- Trim to keep the prompt (and required output) within budget ---
    original_counts = (len(timeline), len(evidence_graph), len(baseline_evidence_graph))
    timeline = timeline[:MAX_TIMELINE_EVENTS]
    evidence_graph = evidence_graph[:MAX_EVIDENCE_PROCESSES]          # already sorted by score, most suspicious first
    baseline_evidence_graph = baseline_evidence_graph[:MAX_BASELINE_PROCESSES]

    print(f"[+] Trimmed input: timeline {original_counts[0]}->{len(timeline)}, "
          f"evidence_graph {original_counts[1]}->{len(evidence_graph)}, "
          f"baseline_evidence_graph {original_counts[2]}->{len(baseline_evidence_graph)}")

    print(f"[+] Sending {len(timeline)} timeline events / "
          f"{len(evidence_graph)} incident processes / "
          f"{len(baseline_evidence_graph)} baseline processes to {LLM_MODEL} for reasoning...")

    result = run_llm_reasoning(
        client, timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score
    )

    Path(output_file).write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\nLLM REASONING COMPLETE")
    print(f"What Happened : {result.get('what_happened')}")
    attribution = result.get("attribution") or {}
    if isinstance(attribution, dict):
        print(f"Attribution   : {attribution.get('possible_actor_or_family')} "
              f"(confidence: {attribution.get('confidence')})")
    print(f"\n[OK] Saved to: {output_file}")

    return result


# =============================================================================
# ============================  UNIFIED MAIN  =================================
# =============================================================================

# Sensible fallbacks matching the original scripts' hardcoded Colab paths.
# Override all of these with the CLI flags below for real runs.
DEFAULT_PRE_INPUT_FOLDER = r"/content/drive/MyDrive/dataset/Asynrat/dataset_pre/dataset_pre"
DEFAULT_PRE_MERGED_OUT = "/content/drive/MyDrive/dataset/Asynrat/pre_merged.json"
DEFAULT_PRE_FEATURES_OUT = "/content/drive/MyDrive/dataset/Asynrat/pre_features.json"

DEFAULT_DURING_INPUT_FOLDER = r"/content/drive/MyDrive/dataset/Asynrat/dataset_during/dataset_during"
DEFAULT_DURING_MERGED_OUT = "/content/drive/MyDrive/dataset/Asynrat/during_merged.json"
DEFAULT_DURING_FEATURES_OUT = "/content/drive/MyDrive/dataset/Asynrat/during_features.json"

DEFAULT_BASELINE_OUT = "/content/drive/MyDrive/dataset/Asynrat/baseline_comparison.json"
DEFAULT_SCORING_OUT = "/content/drive/MyDrive/dataset/Asynrat/scoring.json"

DEFAULT_PRE_EVIDENCE_OUT = "/content/drive/MyDrive/dataset/Asynrat/pre_evidence.json"
DEFAULT_DURING_EVIDENCE_OUT = "/content/drive/MyDrive/dataset/Asynrat/during_evidence.json"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Merge Velociraptor/Volatility artifact exports into a "
                    "per-process JSON, then compute detection features from "
                    "that merged result directly (no intermediate file read). "
                    "Runs the merge+extract pipeline separately for a PRE "
                    "dataset folder and a DURING dataset folder -- each is "
                    "scanned, merged, and feature-extracted independently, "
                    "with its own output files. Both folders are searched "
                    "recursively, so it doesn't matter how many snapshot/"
                    "results subfolders sit underneath them."
    )

    # ---- PRE dataset ----
    parser.add_argument("--pre-input-folder", default=DEFAULT_PRE_INPUT_FOLDER,
                         help="PRE dataset folder to recursively scan for artifact JSON/CSV files.")
    parser.add_argument("--pre-merged-out", default=DEFAULT_PRE_MERGED_OUT,
                         help="Where to write the PRE merged per-process JSON (also kept for audit).")
    parser.add_argument("--pre-features-out", default=DEFAULT_PRE_FEATURES_OUT,
                         help="Where to write the PRE final features JSON.")

    # ---- DURING dataset ----
    parser.add_argument("--during-input-folder", default=DEFAULT_DURING_INPUT_FOLDER,
                         help="DURING dataset folder to recursively scan for artifact JSON/CSV files.")
    parser.add_argument("--during-merged-out", default=DEFAULT_DURING_MERGED_OUT,
                         help="Where to write the DURING merged per-process JSON (also kept for audit).")
    parser.add_argument("--during-features-out", default=DEFAULT_DURING_FEATURES_OUT,
                         help="Where to write the DURING final features JSON.")

    # ---- shared across both runs ----
    parser.add_argument("--known-malware-mutex", default=None,
                         help="Optional path to a text file of known-malware mutex substrings, one per line.")
    parser.add_argument("--known-dll-baseline", default=None,
                         help="Optional path to a text file of known/baseline DLL names, one per line.")

    # ---- STAGE 3: baseline compare (pre vs during) ----
    parser.add_argument("--baseline-out", default=DEFAULT_BASELINE_OUT,
                         help="Where to write the PRE-vs-DURING baseline comparison JSON.")
    parser.add_argument("--spike-multiplier", type=float, default=2.0,
                         help="A count field is flagged as a spike if current >= baseline * this multiplier.")
    parser.add_argument("--spike-min-delta", type=int, default=5,
                         help="Minimum absolute increase required before a count change can be marked a spike.")
    parser.add_argument("--top-n", type=int, default=15,
                         help="How many top-anomaly-score entries to print to the console.")
    parser.add_argument("--skip-baseline-compare", action="store_true",
                         help="Run PRE and DURING merge+extract only; skip the baseline comparison stage.")

    # ---- STAGE 4: anomaly scoring (z-score, pre vs during) ----
    parser.add_argument("--scoring-out", default=DEFAULT_SCORING_OUT,
                         help="Where to write the PRE-vs-DURING z-score anomaly scoring JSON.")
    parser.add_argument("--skip-scoring", action="store_true",
                         help="Skip the z-score anomaly scoring stage.")

    # ---- STAGE 5: evidence builder (pre and during, each separately) ----
    parser.add_argument("--pre-evidence-out", default=DEFAULT_PRE_EVIDENCE_OUT,
                         help="Where to write the PRE evidence report JSON.")
    parser.add_argument("--during-evidence-out", default=DEFAULT_DURING_EVIDENCE_OUT,
                         help="Where to write the DURING evidence report JSON.")
    parser.add_argument("--skip-evidence", action="store_true",
                         help="Skip the evidence-builder stage for both PRE and DURING.")

    # ---- run only one side if you want ----
    parser.add_argument("--skip-pre", action="store_true",
                         help="Skip the PRE dataset run and only process DURING.")
    parser.add_argument("--skip-during", action="store_true",
                         help="Skip the DURING dataset run and only process PRE.")

    # ---- STAGE 6: threat intel (PCAP / Sysmon IoC extraction + enrichment) ----
    parser.add_argument("--pcap", type=str, default=None,
                         help="Path to input .pcap file for STAGE 6 threat-intel IoC extraction "
                              "(optional if --sysmon is given). Omit both to skip STAGE 6 entirely.")
    parser.add_argument("--sysmon", type=str, default=None,
                         help="Path to input Sysmon CSV file for STAGE 6 threat-intel IoC extraction "
                              "(optional if --pcap is given).")
    parser.add_argument("--extracted-out", type=str, default="extracted_iocs.json",
                         help="STAGE 6 output path for the filtered/raw IoC list (default: extracted_iocs.json)")
    parser.add_argument("--intel-out", type=str, default="threat_intel_output.json",
                         help="STAGE 6 output path for the enriched threat intel results "
                              "(default: threat_intel_output.json)")
    parser.add_argument("--max-iocs", type=int, default=TI_MAX_IOCS,
                         help=f"STAGE 6: max number of IoCs to enrich, to respect API rate limits "
                              f"(default: {TI_MAX_IOCS})")
    parser.add_argument("--ioc-delay", type=float, default=TI_API_DELAY_SECONDS,
                         help=f"STAGE 6: seconds to wait between enrichment API calls "
                              f"(default: {TI_API_DELAY_SECONDS})")
    parser.add_argument("--skip-threat-intel", action="store_true",
                         help="Skip STAGE 6 even if --pcap/--sysmon are given.")

    # ---- STAGE 7a: fusion score (threat intel + anomaly z-scores) ----
    parser.add_argument("--fusion-threat-in", type=str, default=None,
                         help="STAGE 7a input: enriched threat-intel JSON. "
                              "Defaults to --intel-out if not given.")
    parser.add_argument("--fusion-anomaly-in", type=str, default=None,
                         help="STAGE 7a input: anomaly z-score JSON. "
                              "Defaults to --scoring-out if not given.")
    parser.add_argument("--fusion-out", type=str, default="final_fusion_score.json",
                         help="STAGE 7a output path (default: final_fusion_score.json)")
    parser.add_argument("--skip-fusion-score", action="store_true",
                         help="Skip STAGE 7a (fusion score).")

    # ---- STAGE 7b: host compromise assessment (threat intel only) ----
    parser.add_argument("--host-assessment-in", type=str, default=None,
                         help="STAGE 7b input: enriched threat-intel JSON. "
                              "Defaults to --intel-out if not given.")
    parser.add_argument("--host-assessment-out", type=str, default="final_assessment.json",
                         help="STAGE 7b output path (default: final_assessment.json)")
    parser.add_argument("--skip-host-assessment", action="store_true",
                         help="Skip STAGE 7b (host compromise assessment).")

    # ---- STAGE 8: LLM reasoning engine (Module 13, Google Gemini) ----
    parser.add_argument("--llm-evidence-in", type=str, default=None,
                         help="STAGE 8 input: incident evidence JSON. "
                              "Defaults to --during-evidence-out if not given.")
    parser.add_argument("--llm-pre-evidence-in", type=str, default=None,
                         help="STAGE 8 input: pre/baseline evidence JSON (optional). "
                              "Defaults to --pre-evidence-out if not given.")
    parser.add_argument("--llm-baseline-in", type=str, default=None,
                         help="STAGE 8 input: baseline comparison JSON (optional). "
                              "Defaults to --baseline-out if not given.")
    parser.add_argument("--llm-threat-intel-in", type=str, default=None,
                         help="STAGE 8 input: enriched threat-intel JSON. "
                              "Defaults to --intel-out if not given.")
    parser.add_argument("--llm-host-score-in", type=str, default=None,
                         help="STAGE 8 input: fused host-compromise score JSON. "
                              "Defaults to --fusion-out if not given.")
    parser.add_argument("--llm-out", type=str, default="llm_reasoning_output.json",
                         help="STAGE 8 output path (default: llm_reasoning_output.json)")
    parser.add_argument("--skip-llm-reasoning", action="store_true",
                         help="Skip STAGE 8 (LLM reasoning engine).")

    return parser.parse_args()


def run_pipeline(label, input_folder, merged_out, features_out,
                  known_mutex_path=None, known_dll_path=None):
    """
    Runs STAGE 1 (merge) then STAGE 2 (extract) for a single dataset
    folder (either the pre or the during dataset), keeping the merged
    result entirely in memory between the two stages.

    Returns (merged, features) -- both in-memory dicts -- so a caller can
    feed them straight into STAGE 3 (baseline_compare) without re-reading
    any of the merged/features JSON files back off disk.
    """
    print(f"\n{'=' * 70}")
    print(f"[{label}] Scanning: {input_folder}")
    print(f"{'=' * 70}")

    category_files = discover_files(input_folder)

    if not any(category_files.values()):
        print(f"[X] [{label}] No artifact files found under {input_folder} -- skipping.")
        return None, None

    merged = merge(category_files, merged_out)

    features = extract_features(
        merged,
        features_out,
        known_mutex_path=known_mutex_path,
        known_dll_path=known_dll_path,
    )

    print(f"[{label}] Done. Merged -> {merged_out} | Features -> {features_out}")
    return merged, features


def main():
    args = parse_args()

    if args.skip_pre and args.skip_during:
        print("[X] Both --skip-pre and --skip-during were set -- nothing to do.")
        return

    pre_merged, pre_features = None, None
    during_merged, during_features = None, None

    if not args.skip_pre:
        pre_merged, pre_features = run_pipeline(
            "PRE",
            args.pre_input_folder,
            args.pre_merged_out,
            args.pre_features_out,
            known_mutex_path=args.known_malware_mutex,
            known_dll_path=args.known_dll_baseline,
        )

    if not args.skip_during:
        during_merged, during_features = run_pipeline(
            "DURING",
            args.during_input_folder,
            args.during_merged_out,
            args.during_features_out,
            known_mutex_path=args.known_malware_mutex,
            known_dll_path=args.known_dll_baseline,
        )

    # ---- STAGE 3 & 4: need BOTH pre and during to compare ----
    can_compare = not (args.skip_pre or args.skip_during) and pre_features is not None and during_features is not None

    if not can_compare and (not args.skip_baseline_compare or not args.skip_scoring):
        print("\n[!] Skipping baseline comparison and scoring -- both PRE and DURING must "
              "produce features (don't pass --skip-pre / --skip-during, and make sure both "
              "input folders contain artifact files) to produce a comparison.")

    if can_compare and not args.skip_baseline_compare:
        print(f"\n{'=' * 70}")
        print("[BASELINE COMPARE] PRE vs DURING")
        print(f"{'=' * 70}")

        baseline_compare(
            pre_features, during_features,
            pre_merged, during_merged,
            args.baseline_out,
            spike_multiplier=args.spike_multiplier,
            spike_min_delta=args.spike_min_delta,
            top_n=args.top_n,
        )

    if can_compare and not args.skip_scoring:
        print(f"\n{'=' * 70}")
        print("[ANOMALY SCORING] PRE vs DURING")
        print(f"{'=' * 70}")

        anomaly_score(
            pre_features, during_features,
            args.scoring_out,
        )

    # ---- STAGE 5: EVIDENCE BUILDER (pre and during, each fed in-memory, independently) ----
    if not args.skip_evidence:
        if pre_features is not None:
            print(f"\n{'=' * 70}")
            print("[EVIDENCE] PRE")
            print(f"{'=' * 70}")
            evidence_report(pre_features, args.pre_evidence_out, label="PRE")

        if during_features is not None:
            print(f"\n{'=' * 70}")
            print("[EVIDENCE] DURING")
            print(f"{'=' * 70}")
            evidence_report(during_features, args.during_evidence_out, label="DURING")

    # ---- STAGE 6: THREAT INTEL (independent of stages 1-5; runs off --pcap/--sysmon) ----
    if not args.skip_threat_intel:
        if args.pcap or args.sysmon:
            print(f"\n{'=' * 70}")
            print("[THREAT INTEL] PCAP / Sysmon IoC extraction + enrichment")
            print(f"{'=' * 70}")

            run_threat_intel(
                args.pcap, args.sysmon,
                args.extracted_out, args.intel_out,
                max_iocs=args.max_iocs,
                delay=args.ioc_delay,
            )
        else:
            print("\n[i] STAGE 6 (threat intel) skipped -- no --pcap or --sysmon given.")

    # ---- STAGE 7a: FUSION SCORE (threat intel + anomaly z-scores) ----
    if not args.skip_fusion_score:
        fusion_threat_in = args.fusion_threat_in or args.intel_out
        fusion_anomaly_in = args.fusion_anomaly_in or args.scoring_out

        if os.path.exists(fusion_threat_in) and os.path.exists(fusion_anomaly_in):
            print(f"\n{'=' * 70}")
            print("[FUSION SCORE] Threat intel + anomaly scoring")
            print(f"{'=' * 70}")

            run_fusion_score(fusion_threat_in, fusion_anomaly_in, args.fusion_out)
        else:
            print(f"\n[i] STAGE 7a (fusion score) skipped -- missing input(s): "
                  f"{fusion_threat_in} and/or {fusion_anomaly_in}")

    # ---- STAGE 7b: HOST COMPROMISE ASSESSMENT (threat intel only) ----
    if not args.skip_host_assessment:
        host_in = args.host_assessment_in or args.intel_out

        if os.path.exists(host_in):
            print(f"\n{'=' * 70}")
            print("[HOST ASSESSMENT] Threat-intel-only compromise scoring")
            print(f"{'=' * 70}")

            run_host_assessment(host_in, args.host_assessment_out)
        else:
            print(f"\n[i] STAGE 7b (host assessment) skipped -- missing input: {host_in}")

    # ---- STAGE 8: LLM REASONING ENGINE (Module 13) ----
    if not args.skip_llm_reasoning:
        llm_evidence_in = args.llm_evidence_in or args.during_evidence_out
        llm_pre_evidence_in = args.llm_pre_evidence_in or args.pre_evidence_out
        llm_baseline_in = args.llm_baseline_in or args.baseline_out
        llm_threat_intel_in = args.llm_threat_intel_in or args.intel_out
        llm_host_score_in = args.llm_host_score_in or args.fusion_out

        print(f"\n{'=' * 70}")
        print("[LLM REASONING] Module 13 -- Gemini analyst-grade narrative")
        print(f"{'=' * 70}")

        run_llm_module(
            llm_evidence_in, llm_pre_evidence_in, llm_baseline_in,
            llm_threat_intel_in, llm_host_score_in, args.llm_out,
        )


if __name__ == "__main__":
    main()
