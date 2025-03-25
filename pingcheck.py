import subprocess
check=0
def ping_ip(ip_address):
    """
    Ping the given IP address and return True if it is reachable, False otherwise.
    """
    # Use subprocess to run the ping command
    result = subprocess.run(['ping', '-c', '1','-W','10', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Check the return code to determine if the ping was successful
    if result.returncode == 0:
        return True
    else:
        return False

def check_peer_status(peer_list):
    """
    Check the status of each peer in the given list and print the results.
    """
    print("Checking peer status...\n")
    for ip_address,port in peer_list:
        if ping_ip(ip_address):
            print(f"Peer {ip_address} is reachable.")
            check=1
        else:
            print(f"Peer {ip_address} is unreachable.")
            check=0
    return check

# Example usage:
