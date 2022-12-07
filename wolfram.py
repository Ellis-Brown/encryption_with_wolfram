from wolframalpha import Client # pip install wolframalpha
from api_key import api_key
# Create a file called "api_key.py" and put the following in it:
# api_key = "YOUR_API_KEY"

client = Client(api_key)

# Makes a call to Wolfram Alpha to get the result of a^b mod c
def get_exponent_mod_wolfram(base, exponent, mod):
    
    query_string = f"{base} ^ {exponent} mod {mod}"
    res = client.query(query_string)
    result = next(res.results).text
    return int(result)

def factor_wolfram(number):
    query_string = f"factor {number}"
    res = client.query(query_string)
    print(next(res.results).text)
    return next(res.results).text
