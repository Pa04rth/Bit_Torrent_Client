import base64
from urllib.parse import urlparse
import random 
import string 
import urllib
import struct
from bitstring import BitArray
import bencodepy
import socket
import ssl #for solving the https error 
from udp_response import udp_response_decoder #for decoding the error message
from udp_announce_response import udp_announce_response_decoder
import hashlib
from pingcheck import *
import time #for getting the microsecond of the packet send 
def parse_torrent_file(file_path):
    with open(file_path, 'rb') as file:
        torrent_data = bencodepy.bdecode(file.read())

    return torrent_data

#PARSING THE UDP URL
def parse_tracker_url(url):
    # Parse the tracker URL
    parsed_url = urlparse(url)
    
    #to check weather the url is tcp or udp 

    # Check if the URL scheme is 'udp' and the netloc is not empty
    if parsed_url.scheme == 'udp' and parsed_url.netloc:
        # Extract hostname, port, and any additional parameters
        hostname = parsed_url.hostname
        port = parsed_url.port
        params = parsed_url.params
        type_of_url="udp"
        path = parsed_url.path

        # Print or return the extracted information
        print(f"Hostname: {hostname}")
        print(f"Port: {port}")
        print(f"Additional Parameters: {params}")
        print(f"Type : {type_of_url} ")
        print(f"Path : {path}")
        return hostname, port, params,type_of_url,path
    
    #Check if the URL scheme is for TCP 
    elif parsed_url.scheme.lower() =="http" or parsed_url.scheme.lower() == "https":
        print ("TCP connection is required")
        hostname = parsed_url.hostname
        if parsed_url.port == None:
            if parsed_url.scheme.lower() == "http":
                port=80
            else:
                port=443
        else:
            port = parsed_url.port
            
        params = parsed_url.params
        path = parsed_url.path
        type_of_url = "tcp" 

        # Print or return the extracted information
        print(f"Hostname: {hostname}")
        print(f"Port: {port}")
        print(f"Additional Parameters: {params}")
        print(f"Type : {type_of_url} ")
        print(f"Path : {path}")
        
        return hostname, port, params,type_of_url,path
        
    else:
        print("Invalid UDP tracker URL")
        return None, None, None ,None ,None # Return placeholders for invalid URL


# def validate_udp_tracker_url(url, port):
#     try:
#         #creating a UDP socket 
#         client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
#         client_socket.settimeout(15)
#         client_socket.sendto(b'announce',(socket.gethostbyname(url),port))
#         response, _ = client_socket.recvfrom(1024)
#         return True
#     except Exception as e:
#         print("Invalid UDP tracker URL:", e)
#         return False
#     finally:
#         client_socket.close()
        
def peer_list_extractor(response_bytes):

# Assume each peer entry is 6 bytes long: 4 bytes for the IP address and 2 bytes for the port
   peer_size = 6

# Calculate the number of peers in the response
   num_peers = (len(response_bytes) - 20) // peer_size  # Subtract 20 bytes for the header

# Extract peer information
   peers = []
   for i in range(num_peers):
      peer_start = 20 + (i * peer_size)  # Start position of the peer entry
      peer_ip = response_bytes[peer_start:peer_start + 4]
      peer_port = struct.unpack("!H", response_bytes[peer_start + 4:peer_start + 6])[0]
      peer_address = (socket.inet_ntoa(peer_ip), peer_port)
      peers.append(peer_address)

   print("Peer list:", peers)
   return peers
def connect_to_udp_tracker(hostname,port,message,info_hash):
    try:
        peer_id = b'liutorrent1234567890'
        #creating a UDP socket 
        client_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        client_socket.connect((hostname,port))
        client_socket.settimeout(50)
        connection_id = 0x41727101980  # Magic constant for connection request
        action = 0  # Connect action
        transaction_id = 123456  # Random transaction ID
        packet = struct.pack("!QII", connection_id, action, transaction_id)
        client_socket.send(packet)
        
        # client_socket.sendto(message.encode(),(socket.gethostbyname(hostname),port))
        # Receive and parse connection response
        response = client_socket.recv(16)
        print("\n")
        print("Tracker connection Response (RAW):-",response)
        
        print("Decoded Response From tracker:-\n ")
        udp_response_decoder(response)
        connection_id = struct.unpack("!Q", response[8:])[0]
        print("Connection ID given by UDP Tracker",connection_id)
        print("\n")

        # Construct and send the announce request packet
        action = 1  # Announce action
        packet = struct.pack("!QII20s20sQQQiiiiH", connection_id, action, transaction_id, 
                               info_hash, peer_id, 0, 0, 0, 0, port, -1, 0, 2)
        client_socket.send(packet)
        

    # Receive and parse announce response
        response = client_socket.recv(4096)
        #decoded_response=bencodepy.bdecode(response)
        print("Tracker announce Response:",response)
        peer_info=udp_announce_response_decoder(response)
        peer_list=peer_list_extractor(peer_info)
        return peer_list
        
        # #Number of peices
        # print("Decoded Peers list :- ")
        # for values in peer_list:
        #     print(values)
        # for peer_ip, peer_port in peer_list:
        #     print("\n")
        #     print(f"IP: {peer_ip}, Port: {peer_port}")
        #     print("\n")
        #     print("Connecting to this IP and Port :--")
        #     # Since UDP is connectionless, each request and response is 
        #     # typically sent as a separate datagram (UDP packet)
        #     peer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #     peer_socket.connect((peer_ip, peer_port))
    except socket.error as e:
        print(f"Error: {e}")
        peer_list=[]
        return peer_list

    finally:
        # Close the socket
        client_socket.close()

def request_piece(ip,port,info_hash,peer_id,piece_index):
    #Create a connection request message
    print("Hello")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip,port))
    #IMPLIMENTING THE UTORRENT TRANSFER PROTOCOL 
    # connection_id = b'0x41727101980'  # Magic constant for connection request
    connection_id = b'4681251032576'
    type = 0 # 0 for handshake, 1 for data
    ver = 1 # protocol version
    extension = 0 # extension bits
    
    timestamp_microseconds = int(time.time() *1000000) #  to get timestamp in microseconds
    timestamp_difference_microseconds = 0 # timestamp difference in microseconds
    wnd_size = 0 # window size
    seq_nr = 1 # sequence number
    ack_nr = 0 # acknowledgement number
    
    # Define the header format
    HEADER_FORMAT = ">BBH16sQQLLL"

    # Pack the fields into a packet
    packet = struct.pack(HEADER_FORMAT, type, ver, extension, connection_id, timestamp_microseconds, timestamp_difference_microseconds, wnd_size, seq_nr, ack_nr)
    
    sock.send(packet)
    response =sock.recv(1024)
    print("Raw response")
    print(response)
    
    # action = 0  # Connect action
    # transaction_id = 123456  # Random transaction ID
    # packet = struct.pack("!QII", connection_id, action, transaction_id)
    # sock.sendto(packet,(ip,port))
    # print("Send ho gya")
    # # Receive and parse connection response
    # response = sock.recvfrom(16)
    # print("recieve nhi hua ")
    # print("\n")
    # print("Tracker connection Response (RAW):-",response)    
    # print("Decoded Response From tracker:-\n ")
    # udp_response_decoder(response)
    # connection_id = struct.unpack("!Q", response[8:])[0]
    # print("Connection ID given by UDP Tracker",connection_id)
    # print("\n")
    
    # # Construct and send the announce request packet
    # action = 1  # Announce action
    # packet = struct.pack("!QII20s20sQQQiiiiH", connection_id, action, transaction_id, 
    #                            info_hash, peer_id, 0, 0, 0, 0, port, -1, 0, 2)
    # sock.send(packet)
        

    # # Receive and parse announce response
    # response = sock.recv(4096)
    #     #decoded_response=bencodepy.bdecode(response)
    # print("Tracker announce Response:",response)
    # peer_info=udp_announce_response_decoder(response)
    
    # #Now request a piece from the peer
    # action =2
    
    # piece_req = struct.pack("!QLL", connection_id, action, transaction_id, piece_index)
    # sock.send(piece_req)
    # piece_resp = sock.recv(4096)
    # # Check the action code
    # if int.from_bytes(piece_resp[8:12], "big") != action:
    #     raise Exception("action code mismatch")

    # Get the piece data
    # piece_data = piece_resp[16:] # Get the piece data
    
    # return piece_data

# GENRATING PEER ID FOR THE TCP CONNECTION 
def generate_peer_id(client_id="-UT"):
    random_part='0001'+''.join(random.choice(string.ascii_letters+string.digits) for i in range(13))
    return f"{client_id}{random_part}"



def connect_to_tcp_tracker(hostname, port, info_hash, path):
    peer_id = 'liutorrent1234567890'
    print("Generated Peer ID:", peer_id)
    
    # Create an SSL context
    ssl_context = ssl.create_default_context()
    
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # Connect to the server
        client_socket.connect((hostname, port))
        
        # Wrap the socket with SSL
        ssl_socket = ssl_context.wrap_socket(client_socket, server_hostname=hostname)
        
        # Base64 encode the username and password for basic authentication
        username='user'
        password ='pass'
        auth_str = f"{username}:{password}"
        auth_str_bytes = auth_str.encode('utf-8')
        base64_auth_str = base64.b64encode(auth_str_bytes).decode('utf-8')
        query_params = {
            'info_hash': info_hash,
            'peer_id': peer_id,
            'port': port,
            'uploaded': 0,
            'downloaded': 0,
            'left': 0,
            'compact': 1,  # Indicates that the client wants compact peer lists
            'no_peer_id': 0,
            'event': 'started'  # Event indicating the start of the download
        }
        
        query_string = urllib.parse.urlencode(query_params)
        request_line = f"GET {path}?{query_string} HTTP/1.1\r\n"
        host_line = f"Host: {hostname}\r\n"
        auth_line = f"Authorization: Basic {base64_auth_str}\r\n"
        connection_line = "Connection: close\r\n\r\n"

        # Send the GET request to the tracker
        ssl_socket.sendall((request_line + host_line+ auth_line + connection_line).encode())

        # Receive and print the tracker's response
        response = ssl_socket.recv(4096)
        print("\n")
        print("GENERATED RESPONSE IS :-")
        print("RAW response....")
        print(response)
        print("\n")
        print("Decoded response is :-")
        print(response.decode())
        
        
        print("\n")
        print("DECODED RESPONSE IS :-")
        # Extracting the important information from the decoded response
        extracted_string = response.find(b'\r\n\r\n') + 4
        bencoded_string = response[extracted_string:]
        decoded_response = bencoded_string
        print(decoded_response)
        if decoded_response== b'2a\r\nd14:failure reason20:unregistered torrente\r\n0\r\n\r\n':
            decoded_response="Error"
    finally:
        # Close the socket
        client_socket.close()
    
    return decoded_response, peer_id


# USING THE RESPONSE TO GET THE IPS 
def decode_peers(peers_data):
    # Check if the peers_data is not empty
    if not peers_data:
        return []

    # Initialize an empty list to store the decoded IP addresses
    decoded_peers = []

    # Iterate through the compact representation (each peer is 6 bytes)
    for i in range(0, len(peers_data), 6):
        # Extract the 4-byte IP address and 2-byte port
        ip_bytes = peers_data[i:i+4]
        port_bytes = peers_data[i+4:i+6]

        # Convert the byte sequences to integers
        ip = ".".join(str(byte) for byte in ip_bytes)
        port = struct.unpack('>H', port_bytes)[0]

        # Append the decoded IP address and port to the list
        decoded_peers.append((ip, port))

    return decoded_peers

import struct

def send_interested(peer_socket):
    interested_message = struct.pack('>Ib', 1, 2)  # Message length (1) + Message ID (2 for "interested")
    peer_socket.send(interested_message)

def receive_interested(peer_socket):
    interested_data = peer_socket.recv(5)  # 4 bytes for message length + 1 byte for message ID
    message_length, message_id = struct.unpack('>Ib', interested_data)

    if message_id == 2:  # Message ID 2 corresponds to "interested"
        print("Peer is interested.")
        return 1

def peer_handshake_udp(peer_ip, peer_port, info_hash, peer_id):
    return 0
def peer_handshake_http(peer_ip, peer_port, info_hash, peer_id):
    peer_connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    encoded_peer_id = peer_id.encode('utf-8')
    
    try:
        peer_connect.settimeout(100)
        peer_connect.connect((peer_ip, peer_port))
        
        print("CONNECTION WITH THE PEER IS SUCCESSFUL.... ")
        print("STARTING A HANDSHAKE .....")
        
        pstr = b"BitTorrent protocol"
        reserved = b'\x00' * 8
        
        # Corrected handshake format
        handshake_format = ">B19s8x20s20s"
        handshake = struct.pack(handshake_format, len(pstr), pstr , info_hash, encoded_peer_id)
        print(handshake)
        peer_connect.sendall(handshake)
        print("Handshake successful with the peer.")
        
        print("Response from the peer is :-")
        response = peer_connect.recv(68)
        print(response)
        
        print("Extracting useful information from the response :-")
        peerid_len = len(peer_id)
        extracted_peer_id = response[-peerid_len:]
        print("Extracted Peer ID :-", extracted_peer_id.decode('utf-8'))
        
        extracted_info_hash = response[28:48]
        print("Extracted Info Hash :-", extracted_info_hash)
        print("\nCHECKING IF THE INFO HASH IS VALID:-")
        
        if extracted_info_hash == info_hash:
            print("Valid,sending the interested message .....")
            send_interested(peer_connect)
            print("Recieving the Interested message..")
            a=receive_interested(peer_connect)
            if a==1:
                print("Interested")
                return peer_connect
        else:
            print("Invalid")
            return "Not Interested"
    except socket.error as e:
        print(f"Socket error connecting to {peer_ip}:{peer_port}: {e}")
    except Exception as e:
        print(f"Error connecting to {peer_ip}:{peer_port}: {e}")
    finally:
        peer_connect.close()

def send_bitfield_msg(peer_socket,bitfield):
    # Determine the length of the bitfield in bytes
    bitfield_length = (len(bitfield) + 7) // 8

    # Construct the Bitfield message
    message_id = 5
    bitfield_message = struct.pack("!IB", bitfield_length + 1, message_id) + bitfield

    # Send the Bitfield message to the peer
    peer_socket.sendall(bitfield_message)
    

    

def final(announce_url_list,parsed_data):
    for inner_list in announce_url_list:
        print("\n")
        print("............................................................................................")
        print("TAKING THE URL:-")
        # Access the string from the inner list before parsing the URL
        print(inner_list)
        hostname, port, params,type,path = parse_tracker_url(inner_list)
        info_hash = b'T3GUM5X5B4CHIFI2JN2KLFMPIJRZZ267'
        
        
        
        if type=="udp":
            if hostname is not None and port is not None:
                peer_id = '-liutorrent1234567890' 
                print("Reached above connect_to_udp_tracker")
                peer_list=connect_to_udp_tracker(hostname, port, "connect",info_hash=info_hash)
                print(peer_list)
                if peer_list != None :
                        print("Decoded Peers list :- ")
                        for values in peer_list:
                           print(values)
                        for ip, port in peer_list:
                            print("\n")
                            print(f"IP: {ip}, Port: {port}")
                            print("\n")
                            print("Connecting to this IP and Port :--")
                            request_piece(ip,port,info_hash, peer_id, None)
                            
                        #Lets create a list of peices to be downloaded 
                        # pieces =[]
                        # num_of_pieces=parsed_data[b'info'][b'piece length']
                        # print("Number of pieces to download:",num_of_pieces)
                        # for i in range(num_of_pieces):
                        # #Loop through the list of peer for the peice
                        #     for ip,port in peer_list:
                        #     #Try request a peice from each peer
                        #         try:
                        #             print("...")
                        #             piece_data = request_piece(ip,port,info_hash, peer_id, i)
                        #             print(piece_data)
                        #             # Check the hash of the piece
                        #             piece_hash = hashlib.sha1(piece_data).digest()
                        #             if piece_hash == parsed_data['info']['pieces'][i * 20:(i + 1) * 20]:
                        #                 # The piece is valid, append it to the list
                        #                 pieces.append(piece_data)
                        #                 # Break the inner loop
                        #                 break
                        #             else:
                        #             # The piece is invalid, raise an exception
                        #                 raise Exception("hash mismatch")
                        #         except Exception as e:
                        #              # Something went wrong, print the error and continue the inner loop
                        #             print(f"Error requesting piece {i} from peer {ip},{port}: {e}")
                        #             continue
                        #             # Check if the piece was downloaded
                        # if len(pieces) == i + 1:
                        #          # The piece was downloaded, print a message
                        #     print(f"Downloaded piece {i} successfully")
                        # else:
                        #     # The piece was not downloaded, print a message and exit the program
                        #     print(f"Failed to download piece {i} from any peer")                     
        else :
            print("It is an TCP tracker URL")
            
            decoded_response,peer_id=connect_to_tcp_tracker(hostname,port,info_hash,path)
            if decoded_response =="Error":
                print("Using next url......")
                continue 
            else:
                peers_data = decoded_response.get(b'peers', b'')
                decoded_peers = decode_peers(peers_data)
            
                print("\n")
                print("Decoded Peers list :- ")
                for values in decoded_peers:
                    print(values)
            
                
                for ip, port in decoded_peers:
                    print("\n")
                    print(f"IP: {ip}, Port: {port}")
                    print("\n")
                    print("Connecting to this IP and Port :--")
                    handshake_response=peer_handshake_http(ip,port,info_hash,peer_id)
                    if handshake_response == "Interested":
                        print("Peer is interested. Exiting the 'final' function.")
                        return ip,port
                    else:
                        print("None")
                
                
                
        
                
# Example usage
torrent_file_path = "C:\\DRIVE\MY STUDY\\PROJECTS\\BIT_TORRENT_\\ubuntu.torrent"
parsed_data = parse_torrent_file(torrent_file_path)

#To print all the parsed data 
print(parsed_data)




# Access specific values from the parsed data with error handling
try:

    print("INFO :")
    for index, values in enumerate(parsed_data[b'info']):
     print(f"Index: {index}, Values: {values} \n")
         
    print("\n")
    
    # FIRST CHECK FOR THE FIELD AND THEN PRINT 
    creation_date = b'creation date'
    if creation_date in parsed_data:
        print("CREATION DATE :",parsed_data[b'creation date'])
    else:
        print("NO CREATION DATE GIVEN")
        
    print("\n")
    created_by = b'created by'
    if created_by in parsed_data:
        print("CREATED BY :",parsed_data[b'created by'].decode())
    else:
        print("CREATED BY IS NOT GIVEN ")
    print("\n")
    name= b'name'
    info_dict= parsed_data[b'info']
    if name in info_dict:
        print("NAME: ", parsed_data[b'info'][b'name'].decode())
    else:
        print("NO NAME GIVEN ")
    print("\n")
    print("PIECE LENGTH :-",parsed_data[b'info'][b'piece length'])
    print("\n")
    #ENCODED PEICES DATA- (ABHI ISKI JAROORAT NHI HAI) 
    # peices_raw= parsed_data[b'info'][b'pieces']
    # print("PIECES:",peices_raw)
    
    print("TRACKER URL/ANNOUNCE LIST:")
    inner_values = [inner.decode('utf-8') for outer in parsed_data[b'announce-list'] for inner in outer]

    for inner_inner_values in inner_values:
        print(inner_inner_values)
    
        
    print ("\n")
    # PRINTING TRACKER URL IN THE DECODED WAY (BYTE STREAM -> NORMAL STRING )
    byte_string_url=parsed_data[b'announce']
    tracker_url=byte_string_url.decode('utf-8')
    print("Tracker URL:", tracker_url)
    
    #HANDLING THE EXCEPTION
except KeyError as e:
    print(f"Error accessing key: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
    

    
print("\n")
ip,port=final(inner_values,parsed_data)
    
# print("Now further procedure ")
# print("Sending the Bitfield message ....")
# peer_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# peer_socket.connect((ip,port))

# pieces=parsed_data[b'info'][b'pieces']
    
# piece_length = 20 
# num_pieces = len(pieces)// piece_length
# peices_list =[pieces[i*piece_length:(i+1)*piece_length] for i in range(num_pieces)]
#     # print("Pieces:-")
    
#     # for values in peices_list:
#     #     hash_integer = int.from_bytes(values, byteorder='big')
#     #     print(hash_integer)
    
# bit_array_pieces = BitArray(bin='0' * num_pieces)
# print(bit_array_pieces)
# send_bitfield_msg(peer_socket,bit_array_pieces)
   
    
