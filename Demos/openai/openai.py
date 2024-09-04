import os
import json
import requests
from dotenv import load_dotenv


def prompt_openai(role_prompt, prompt, api_key, model="gpt-4o-mini", debug=False):

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": role_prompt},
                {"role": "user", "content": prompt},
            ],
        },
    )

    if response.status_code != 200:
        raise Exception(f"Failed to prompt GPT: {response.json()}")

    if debug:
        print("Response:")
        print("--------------------")
        print(json.dumps(response.json(), indent=4))
        print("--------------------")

    return response.json()["choices"][0]["message"]["content"]


def main():
    load_dotenv()
    openai_api_key = os.getenv("OPENAI_API_KEY")

    system_prompt = "You make fun of of whoever is in front of you."
    prompt = "Hi! I own a jetski"

    response = prompt_openai(system_prompt, prompt, openai_api_key)

    print("--------------------")
    print(response)
    print("--------------------")


if __name__ == "__main__":
    main()
