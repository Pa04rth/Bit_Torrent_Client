# def info_hash_to_bytes(info_hash_hex):
#     # Remove any leading or trailing whitespaces
#     info_hash_hex = info_hash_hex.strip()
    
#     # Check if the length of the hexadecimal string is valid
#     if len(info_hash_hex) % 2 != 0:
#         raise ValueError("Invalid info hash length")
    
#     # Convert the hexadecimal string to bytes
#     info_hash_bytes = bytes.fromhex(info_hash_hex)
    
#     return info_hash_bytes

# # Example usage
# info_hash_hex = "T3GUM5X5B4CHIFI2JN2KLFMPIJRZZ267"
# info_hash_bytes = info_hash_to_bytes(info_hash_hex)
# print("Info hash in bytes:", info_hash_bytes)

info_hash_str = "T3GUM5X5B4CHIFI2JN2KLFMPIJRZZ267"
info_hash_bytes = info_hash_str.encode('utf-8')
print(info_hash_bytes)

