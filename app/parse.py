# app/parse.py
import pyshark
import pandas as pd
import asyncio
asyncio.set_event_loop(asyncio.new_event_loop())

def load_pcap(file_path, packet_limit=100):
    print(f"Loading: {file_path}")
    capture = pyshark.FileCapture(file_path, use_json=True)

    packets = []
    for i, packet in enumerate(capture):
        try:
            info = {
                'number': i,
                'protocol': packet.highest_layer,
                'src': packet.ip.src,
                'dst': packet.ip.dst,
                'length': packet.length,
                'info': str(packet)
            }
            packets.append(info)
        except AttributeError:
            continue
        if i >= packet_limit:
            break

    df = pd.DataFrame(packets)
    return df
