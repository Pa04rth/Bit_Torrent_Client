# Given response
def udp_response_decoder(response_bytes):

# Extracting action ID or message length
  action_id_or_length = int.from_bytes(response_bytes[:4], byteorder='big')

# Extracting error code or identifier
  transaction_id = int.from_bytes(response_bytes[4:8], byteorder='big')
  connection_id = response_bytes[8:]


# Printing decoded information
  print("Action ID :", action_id_or_length)
  print("Transaction ID:", transaction_id)
  print("Connection ID:", connection_id)
