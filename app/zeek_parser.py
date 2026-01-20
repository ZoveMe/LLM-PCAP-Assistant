from pathlib import Path
import pandas as pd


def _load_zeek_tsv(log_path: Path) -> pd.DataFrame:
    """
    Load a Zeek TSV log that contains '#fields' header.
    """
    if not log_path.exists():
        return pd.DataFrame()

    fields = None
    rows = []

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue

            if line.startswith("#"):
                continue

            if fields is None:
                raise RuntimeError(f"{log_path.name} missing #fields header")

            parts = line.split("\t")
            if len(parts) < len(fields):
                parts += [""] * (len(fields) - len(parts))
            elif len(parts) > len(fields):
                parts = parts[: len(fields)]

            rows.append(parts)

    return pd.DataFrame(rows, columns=fields)


def load_conn_log(zeek_dir: str) -> pd.DataFrame:
    df = _load_zeek_tsv(Path(zeek_dir) / "conn.log")
    keep = [c for c in [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state"
    ] if c in df.columns]
    return df[keep] if keep else df


def load_dns_log(zeek_dir: str) -> pd.DataFrame:
    df = _load_zeek_tsv(Path(zeek_dir) / "dns.log")
    keep = [c for c in [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "query", "qclass_name", "qtype_name", "rcode_name", "answers"
    ] if c in df.columns]
    return df[keep] if keep else df


def load_http_log(zeek_dir: str) -> pd.DataFrame:
    df = _load_zeek_tsv(Path(zeek_dir) / "http.log")
    keep = [c for c in [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "method", "host", "uri", "status_code", "user_agent"
    ] if c in df.columns]
    return df[keep] if keep else df
