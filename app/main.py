from app.parse import load_pcap
from app.llm_engine import ask_llm

file = "app/test1-50 paketi.pcap"  # Exact relative path
df = load_pcap(file, packet_limit=50)

print("📦 First 5 packets loaded:")
print(df.head())

question = input("\n💬 What do you want to ask the LLM about this capture?\n> ")

answer = ask_llm(question, df)

print("\n🧠 LLM Response:")
print(answer)
