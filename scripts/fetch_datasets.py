"""Fetch attack telemetry that Sentinel did not author.

The credibility of the whole project rests on this. If the sample logs were
hand-written to produce a tidy timeline, the derived timeline proves nothing —
a reviewer who knows Windows internals would spot it immediately.

These samples come from EVTX-ATTACK-SAMPLES, real Windows event logs captured
while known techniques were executed against instrumented hosts. Ground truth
(which technique produced which file) is established by the source, not by us,
so detection accuracy is measurable rather than asserted.

    https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

Usage:
    python scripts/fetch_datasets.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

RAW = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master"
DEST = Path(__file__).resolve().parent.parent / "data" / "raw"


@dataclass(frozen=True)
class Sample:
    """One EVTX file and the technique it is known to contain."""

    path: str
    technique: str
    note: str


# Curated to the intrusion narrative Sentinel reconstructs: execution through
# an office document, credential theft from LSASS, persistence via a new
# account, then movement. Kept small on purpose — a handful of files that
# exercise every detector beats hundreds that exercise one.
SAMPLES: tuple[Sample, ...] = (
    Sample(
        "Credential Access/CA_hashdump_4663_4656_lsass_access.evtx",
        "T1003.001",
        "handle opened on lsass.exe, object access auditing",
    ),
    Sample(
        "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx",
        "T1003.001",
        "MiniDumpWriteDump against lsass via powershell script block",
    ),
    Sample(
        "Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx",
        "T1003.001",
        "hashdump through meterpreter, sysmon process view",
    ),
    Sample(
        "Credential Access/babyshark_mimikatz_powershell.evtx",
        "T1003.001",
        "mimikatz invoked from powershell",
    ),
    Sample(
        "Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
        "T1218.011",
        "rundll32 and mshta into a scheduled task, sysmon 1/3/11",
    ),
    Sample(
        "Execution/temp_scheduled_task_4698_4699.evtx",
        "T1053.005",
        "scheduled task registered then removed",
    ),
    Sample(
        "Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx",
        "T1021.002",
        "psexec over smb carrying meterpreter",
    ),
    Sample(
        "Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx",
        "T1047",
        "remote process creation over wmi via impacket",
    ),
)


def fetch(client: httpx.Client, sample: Sample) -> tuple[bool, str]:
    url = f"{RAW}/{quote(sample.path)}"
    target = DEST / Path(sample.path).name

    if target.exists() and target.stat().st_size > 0:
        return True, f"cached  {target.name}"

    try:
        response = client.get(url, follow_redirects=True, timeout=60.0)
    except httpx.HTTPError as exc:
        return False, f"FAILED  {sample.path} ({exc.__class__.__name__})"

    if response.status_code != 200:
        return False, f"FAILED  {sample.path} (HTTP {response.status_code})"

    target.write_bytes(response.content)
    kb = len(response.content) / 1024
    return True, f"ok      {target.name}  {kb:,.0f} KB  {sample.technique}"


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    ok = 0

    with httpx.Client() as client:
        for sample in SAMPLES:
            success, line = fetch(client, sample)
            ok += success
            print(line)

    print(f"\n{ok}/{len(SAMPLES)} samples in {DEST}")
    # Missing files are survivable — the upstream repo reorganises paths
    # occasionally — but zero files is not.
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
