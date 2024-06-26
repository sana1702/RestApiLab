import requests 
from requests.auth import HTTPBasicAuth

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def format_auth_token(token, line_length=64):
    """
    Formats the authentication token into readable lines.

    Parameters: 
    token (str): the authentication token to be formatted. 
    line_length (int): The length of each line. Default is 64 characters.

    Returns: 
    str: The formatted token. 

    """
    formatted_token = '\n'.join(token[i:i + line_length] for i in range (0, len(token), line_length))
    return formatted_token

def get_auth_token():
    """
    Retrieves the authentication token from the endpoint.

    Returns: 
    str: The authentication token. 
    """
    # Endpoint URL
    url = 'https://10.0.223.207'
    
    creds = {
        "userName": "cisco-live-ro",
        "userPasswd": "Ciscolive123",
        "domain": "DefaultAuth"
    }
    # Make the POST Request
    resp = requests.post(url='https://10.0.223.207/login', json=creds, verify=False)
    # Retrieve the Token from the returned JSON
    token = resp.json().get('jwttoken', '')
    # Print out the formatted Token
    formatted_token = format_auth_token(token)
    print("Token Retrieved:\n{}".format(formatted_token))
    # Create a return statement to send the token back for later use
    return token

def format_anomaly_data(anomaly_data):
    """
    Formats the anomaly data into readable text.
    Args:
        endpoint_data (dict): Dictionary containing endpoint information.
    """
    entries = anomaly_data.get('entries', [])
    
    for entry in entries:
        print(f"Severity ID: {entry.get('severity')}")
        print(f"Category: {entry.get('category')}")
        print(f"Sub category: {entry.get('subCategory')}")
        print(f"Mnemoic Title: {entry.get('mnemonicTitle')}")
        print(f"Rule Name: {entry.get('ruleName')}")
        print(f"Rule ID: {entry.get('ruleId')}")
        print(f"Rule Type: {entry.get('ruleType')}")
        print(f"Mnemonic No Name: {entry.get('mnenomicNum')}")
        print(f"Count: {entry.get('count')}")
        print(f"Anomaly String: {entry.get('anomalyStr')}")
        print(f"App Version: {entry.get('appVersion')}")
        print("-" * 40)

def get_anomalies_int():
    """
    Building out function to retrieve device interface. Using requests.get
    to make a call to the network device Endpoint
    """
    token = get_auth_token() 
    url = "https://tme-cls2-nd1/sedgeapi/v1/cisco-nir/api/api/v1/anomalies/details?filter=cleared%3Afalse+AND+acknowledged%3Afalse&siteGroupName=default&siteName=tme-dc3&offset=0&count=10&endDate=2024-06-24T15%3A29%3A31-07%3A00&startDate=2024-06-24T13%3A29%3A31-07%3A00&aggr=mnemonicTitle&siteStatus=online"
    hdr = {'Authorization': token}
    resp = requests.get(url, headers=hdr, verify=False) 
    interface_info_json = resp.json()
    format_anomaly_data(interface_info_json)
    # print(interface_info_json)


if __name__ == "__main__":
    # get_auth_token()
    get_anomalies_int()