
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

def ask_llm(question, context_df):
    context = context_df.to_string(index=False)
    prompt = f"""
I have the following network packets:

{context}

Question: {question}
Answer in simple explanation:
"""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
