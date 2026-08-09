from __future__ import annotations

import os

import google.generativeai as genai

from dotenv import load_dotenv


load_dotenv()


class FinalReportModelError(Exception):
    pass


class FinalReportModel:

    def __init__(self) -> None:

        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise FinalReportModelError(
                "GEMINI_API_KEY not found."
            )

        genai.configure(api_key=api_key)

        self.model = genai.GenerativeModel(
            "gemini-3.5-flash"
        )

    def generate(
        self,
        prompt: str,
    ) -> str:

        try:

            response = self.model.generate_content(prompt)

            if not response.text:
                raise FinalReportModelError(
                    "Empty response from Gemini."
                )

            return response.text

        except Exception as exc:

            raise FinalReportModelError(
                f"Gemini API error: {exc}"
            ) from exc