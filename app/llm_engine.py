import os
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from typing import List

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


class PcapAnswer(BaseModel):
    answer: str = Field(..., description="One short direct answer.")
    summary: List[str] = Field(default_factory=list, description="1-2 short bullet points.")


def ask_llm(question, context_df):
    context = context_df.to_string(index=False)

    system_prompt = (
        "You are a network traffic analysis assistant. "
        "Use ONLY the provided packet table. Do NOT guess or invent information. "
        "Keep the answer short and factual. Summary should be 1-2 bullets."
    )

    user_prompt = f"""PACKETS TABLE:
{context}

QUESTION:
{question}
"""

    # ✅ Structured Outputs parsing (returns PcapAnswer)
    response = client.responses.parse(
        model="gpt-4.1-mini",
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        text_format=PcapAnswer,
    )

    parsed: PcapAnswer = response.output_parsed

    # Safety: ensure summary max 2 items
    parsed.summary = (parsed.summary or [])[:2]

    return parsed.model_dump()
