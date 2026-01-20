import shutil
import subprocess
import tempfile
from pathlib import Path


def find_zeek_executable() -> str:
    """
    Tries to locate Zeek. In WSL it's usually just 'zeek' (in PATH).
    Returns the executable name/path.
    """
    return "zeek"


def run_zeek(pcap_path: str) -> str:
    """
    Runs Zeek on the given pcap file and writes logs into a fresh temp directory.
    Returns the output directory path.

    Raises RuntimeError with stderr if Zeek fails.
    """
    pcap = Path(pcap_path)
    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    out_dir = Path(tempfile.mkdtemp(prefix="zeek_"))

    zeek = find_zeek_executable()

    # Run zeek in the output directory so logs are written there
    cmd = [zeek, "-r", str(pcap)]
    proc = subprocess.run(
        cmd,
        cwd=str(out_dir),
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        # Clean up the directory on failure
        shutil.rmtree(out_dir, ignore_errors=True)
        raise RuntimeError(f"Zeek failed: {proc.stderr.strip() or proc.stdout.strip()}")

    # Minimum expected log
    conn_log = out_dir / "conn.log"
    if not conn_log.exists():
        # Not fatal in some weird cases, but for your project it should exist
        shutil.rmtree(out_dir, ignore_errors=True)
        raise RuntimeError("Zeek ran but did not produce conn.log")

    return str(out_dir)
