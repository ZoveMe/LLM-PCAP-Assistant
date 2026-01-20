# app/parse.py
import asyncio
import pyshark
import pandas as pd


def load_pcap(file_path, packet_limit=100):
    """
    Thread-safe PCAP loader for use with FastAPI + asyncio.to_thread on Windows/Python 3.12.
    PyShark expects an asyncio event loop to exist in the current thread.
    """
    print(f"Loading: {file_path}")

    # ✅ Create and set an event loop for THIS thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.FileCapture(
        file_path,
        use_json=True,
        keep_packets=False,  # ✅ avoid memory blowups
    )

    packets = []
    try:
        for i, packet in enumerate(capture):
            if i >= packet_limit:
                break

            # Some packets have no IP layer; handle safely
            src = None
            dst = None
            if hasattr(packet, "ip"):
                try:
                    src = packet.ip.src
                    dst = packet.ip.dst
                except Exception:
                    pass

            try:
                packets.append({
                    "number": i,
                    "protocol": getattr(packet, "highest_layer", None),
                    "src": src,
                    "dst": dst,
                    "length": getattr(packet, "length", None),
                    # limit verbosity to keep token usage sane
                    "info": str(packet)[:600],
                })
            except Exception:
                continue
    finally:
        # ✅ Always close capture to stop tshark process
        try:
            capture.close()
        except Exception:
            pass

        # ✅ Close the loop we created
        try:
            loop.close()
        except Exception:
            pass

    return pd.DataFrame(packets)
