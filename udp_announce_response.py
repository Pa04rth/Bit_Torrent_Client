def udp_announce_response_decoder(response_bytes):

# Extracting action ID or message length
  action_id_or_length = int.from_bytes(response_bytes[:4], byteorder='big')

# Extracting error code or identifier
  transaction_id = int.from_bytes(response_bytes[4:8], byteorder='big')
  interval=int.from_bytes(response_bytes[8:12], byteorder='big')
  leecher=int.from_bytes(response_bytes[12:16], byteorder='big')
  seeder=int.from_bytes(response_bytes[16:32], byteorder='big')
  peers = response_bytes[32:]


# Printing decoded information
  print("Action ID :", action_id_or_length)
  print("Transaction ID:", transaction_id)
  print("Interval:", interval)
  print("Leecher:", leecher)
  print("Seeder:",seeder)
  return peers