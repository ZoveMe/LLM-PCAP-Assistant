from pathlib import Path
from app.parse import load_pcap
from app.llm_engine import ask_llm

BASE_DIR = Path(__file__).resolve().parent
PCAP_PATH = BASE_DIR / "test1-50 paketi.pcap"

df = load_pcap(str(PCAP_PATH), packet_limit=50)


print("📦 First 5 packets loaded:")
print(df.head())

question = input("\n💬 What do you want to ask the LLM about this capture?\n> ")

answer = ask_llm(question, df)

print("\n🧠 LLM Response:")
print(answer)