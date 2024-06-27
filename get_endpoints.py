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

def format_endpoint_data(endpoint_data):
    """
    Formats the endpoint data into readable text.
    Args:
        endpoint_data (dict): Dictionary containing endpoint information.
    """
    entries = endpoint_data.get('entries', [])
    
    for entry in entries:
        print(f"Endpoint ID: {entry.get('endpointId')}")
        print(f"Tenant: {entry.get('tenant')}")
        print(f"MAC Address: {entry.get('mac')}")
        print(f"IP Address: {', '.join(entry.get('ip', []))}")
        print(f"Node Name: {entry.get('nodeName')}")
        print(f"Interface: {', '.join(entry.get('displayInterface', []))}")
        print(f"Encap: {entry.get('encap')}")
        print(f"VM Name: {entry.get('vmName')}")
        print(f"Creation Time: {entry.get('createTime')}")
        print("-" * 40)

def get_endpoint_int():
    """
    Building out function to retrieve device interface. Using requests.get
    to make a call to the network device Endpoint
    """
    token = get_auth_token() 
    url = "https://tme-cls1-nd1/sedgeapi/v1/cisco-nir/api/api/v1/endpoints?siteGroupName=default&siteName=tme-dc1&offset=0&count=10&sort=-anomalyScore&startDate=2024-06-24T08%3A40%3A29-07%3A00&endDate=2024-06-24T10%3A40%3A29-07%3A00"
    hdr = {'Authorization': token}
    resp = requests.get(url, headers=hdr, verify=False) 
    interface_info_json = resp.json()
    # print(interface_info_json)

    format_endpoint_data(interface_info_json)


if __name__ == "__main__":
    # get_auth_token()
   get_endpoint_int()
#    format_endpoint_data()