import json
import urllib.request
import time

prompt = """
You are a DFIR analyst.

Question:
What type of attack is indicated by the following evidence?

Evidence:
- README_FOR_DECRYPTION.txt found
- vssadmin delete shadows executed
- Many files renamed
- Defender detected ransomware

Answer in less than 100 words.
"""

payload = json.dumps({
    "model": "qwen2.5:14b",
    "prompt": prompt,
    "stream": False,
}).encode()

request = urllib.request.Request(
    "http://localhost:11434/api/generate",
    data=payload,
    headers={"Content-Type": "application/json"},
)

start = time.time()

with urllib.request.urlopen(request, timeout=300) as response:
    body = json.loads(response.read())

print(time.time() - start)
print(body["response"])