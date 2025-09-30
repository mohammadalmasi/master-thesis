import requests
import json
import os

openai_api_key = "" 
if openai_api_key is None:
    raise ValueError("OpenAI API key is not set in environment variables.")

def ask_gpt(code):
    url = "https://api.openai.com/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {openai_api_key}"
    }

    data = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {
            "role": "system",
            "content": "You are a highly intelligent and accurate code analysis assistant."
            },
            {
            "role": "user",
            "content": "Please analyze the following code and provide a response in the format specified. The response should include a summary of the issues found (in bullet points) and a corrected version of the code. If the code is fine, just say there is nothing to improve. Only look for the vulnerabilities, not the optimization. Make sure your response does not exceed 1000 words.\n\nSummary:\n- Bullet points of the issue or improvement\n\nProvide the code which has issues, just give me BULLET POINTS, not anything else, make it short and straight to the point.\n\n<code>\n# "+code+" \n</code>"
            }
        ]
    }

    response = requests.post(url, headers=headers, json=data)

    result = "An error has occured"
    if response.status_code == 200:
        result = response.json()['choices'][0]['message']['content']

    return result