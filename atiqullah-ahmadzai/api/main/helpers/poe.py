from poe_api_wrapper import PoeApi
from main.helpers.functions import *

# Using poe.com tokens
tokens = {
    'p-b': get_env("POE_PB"),
    'p-lat': get_env("POE_LT")
}


def ask_poe(code):
    client = PoeApi(tokens=tokens)
    message = "Please check the below code for issues: "+code
    for chunk in client.send_message(bot="code-checker-sad", message=message):
        pass
        
    return chunk["text"]
