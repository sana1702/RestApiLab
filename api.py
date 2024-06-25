import requests 
from requests.auth import HTTPBasicAuth

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



## Grabs the authentication token for 
def get_auth_token():
    # Endpoint URL
    url = 'https://10.0.223.207'
    creds = {
        "userName": "cisco-live-ro",
        "userPasswd": "Ciscolive123",
        "domain": "DefaultAuth"
    }

    resp = requests.post(url='https://10.0.223.207/login', json=creds, verify=False)
    # Make the POST Request
    # response = requests.post(url, auth=HTTPBasicAuth(dnac_config.DNA_CENTER['userName'], dnac_config.DNA_CENTER['userPasswd']), verify=False)

    # Retrieve the Token from the returned JSON
    print(resp.json())
    token = resp.json()['jwttoken']
    # Print out the Token
    print("Token Retrieved: {}".format(token))
    # Create a return statement to send the token back for later use
    return token
    

if __name__ == "__main__":
    get_auth_token()

