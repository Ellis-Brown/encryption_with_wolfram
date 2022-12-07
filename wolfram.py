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
    res = str(next(res.results).text)
    # NOTE: this is the "×" char not "x"

    index_of_x = res.index("×")
    index_of_space = res.strip().index(" ")
    num_1 = res[:index_of_x] 
    num_2 = res[index_of_x + 1: index_of_space]

    return int(num_1), int(num_2)
