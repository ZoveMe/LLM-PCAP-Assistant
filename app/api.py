from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import tempfile, os, asyncio, shutil

from app.zeek_runner import run_zeek
from app.zeek_parser import load_conn_log, load_dns_log, load_http_log
from app.llm_engine import ask_llm
from app.store import create_session, get_session

app = FastAPI(title="LLM-PCAP-Assistant API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are allowed")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    zeek_dir = None
    try:
        # Run Zeek once
        try:
            zeek_dir = await asyncio.to_thread(run_zeek, tmp_path)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Zeek failed: {e}")

        # Parse logs
        conn_df = await asyncio.to_thread(load_conn_log, zeek_dir)
        dns_df = await asyncio.to_thread(load_dns_log, zeek_dir)
        http_df = await asyncio.to_thread(load_http_log, zeek_dir)

        # Store in memory
        session_id = create_session({
            "conn": conn_df,
            "dns": dns_df,
            "http": http_df,
        })

        # Helpful metadata for UI
        return {
            "session_id": session_id,
            "counts": {
                "conn": int(len(conn_df)),
                "dns": int(len(dns_df)),
                "http": int(len(http_df)),
            }
        }

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        if zeek_dir:
            shutil.rmtree(zeek_dir, ignore_errors=True)


@app.post("/ask")
async def ask_question(
    session_id: str = Form(...),
    question: str = Form(...)
):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired. Upload PCAP again.")

    data = session["data"]
    conn_df = data["conn"]
    dns_df = data["dns"]
    http_df = data["http"]

    # Build context: keep it small and relevant (MVP)
    # Later in Phase 3 we’ll filter based on question.
    parts = []

    if len(conn_df) > 0:
        parts.append(("CONNECTIONS (conn.log)", conn_df.head(80)))
    if len(dns_df) > 0:
        parts.append(("DNS (dns.log)", dns_df.head(60)))
    if len(http_df) > 0:
        parts.append(("HTTP (http.log)", http_df.head(60)))

    if not parts:
        raise HTTPException(status_code=400, detail="No Zeek logs contained usable entries.")

    # Merge into a single table-ish context
    # We'll make a combined DataFrame-like string for now
    context_text = []
    for title, df in parts:
        context_text.append(f"\n=== {title} ===\n")
        context_text.append(df.to_string(index=False))

    # Create a pseudo "context_df" for ask_llm by wrapping text
    # (ask_llm currently expects DataFrame; easiest is to pass a 1-col DF)
    import pandas as pd
    context_df = pd.DataFrame({"zeek_logs": ["\n".join(context_text)]})

    result = await asyncio.to_thread(ask_llm, question, context_df)
    return result
