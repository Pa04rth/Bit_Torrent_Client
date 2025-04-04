import struct # CONVERT THE DATA INTO STREAM OF BYTES 
import socket # USED TO SETUP CONNECTION BETWEEN THE PEERS
from bitstring import BitArray
from collections import deque
MAX_REQUESTS=2
MSG_TYPES=['choke', 'unchoke', 'interested', 'not_interested', 'have', 'bitfield', 'request', 'piece', 'cancel',
             'port']
def encode_msg(msg_type,payload=b''):
    if msg_type=='keep alive ':
        msg=''
    else:
        msg = struct.pack('B', MSG_TYPES.index(msg_type)) + payload
    return struct.pack('>I', len(msg)) + msg

class Peer():
    '''USED FOR PEER HANDLING THE PEERS'''
       #defining the initialising method which sets the initial values for the 
    def __init__(self, torrent,ip,port,peer_id=None):
        #THESE ARE THE FOLLOWING ATTRIBUTES TO THE  CLASS 
        self.torrent = torrent #represent the file to be downloaded 
        self.ip = ip #of the peer
        self.port = port 
        self.peer_id = peer_id
        self.sock = None # used for communication with peer
        self.handshake = '' # used to store handshake message 

        self.state = None
        self.is_chocking = True
        self.am_interested = False
        self.am_choking = True
        self.is_interested = False
        
        self.msg_queue = deque() #used to store incoming messages
        
        #THIS CREATES THE 
        self.pieces = BitArray(bin='0' * self.torrent.num_pieces)
        self.reply = ''

        self.requests = []  # array of tuples: piece, offset
        self.MAX_REQUESTS = MAX_REQUESTS
        self.MAX_MSG_LEN = 2 ** 15
    
    def fileno(self):
        """
        makes Peer object behave like i/o object that can be handled by select
        will only work once self.sock has been created
        """
        return self.sock.fileno()

    def connect(self):
        if not self.sock:
            self.sock = socket.socket()  # create a socket for him
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # set socket reuse
        self.sock.setblocking(False)  # make the socket non-blocking
        try:
            self.sock.connect((self.ip, self.port))  # connect
        except socket.error:  # maybe log this
            pass
        finally:
            self.state = 'sending_to_wait'

    def read(self):
        """receive a reply from peer"""
        try:
            self.reply += self.sock.recv(self.MAX_MSG_LEN)
        except socket.error:
            pass
        finally:
            self.process_reply()

    def write(self):
        self.enqueue_msg()
        self.send_msg()

    def process_reply(self):
        while self.reply != '':
            if ord(self.reply[0]) == 19 and self.reply[1:20] == 'BitTorrent protocol':
                self.process_handshake(self.reply[:68])
                self.reply = self.reply[68:]
            else:
                msg_len = struct.unpack('>I', self.reply[:4])[0]
                if msg_len == 0:
                    print('Keep alive')
                    # TODO: keep alive: reset the timeout; update self.reply
                    self.reply = self.reply[:4]
                elif len(self.reply) >= (msg_len + 4):
                    self.process_msg(self.reply[4:4 + msg_len])
                    self.reply = self.reply[4 + msg_len:]
                else:
                    break

    def enqueue_msg(self):
        if self.state == 'sending_to_wait':
            self.msg_queue.append(self.torrent.handshake)
            self.state = 'waiting'
            print('Enq Handshake')
        elif self.state == 'connected':
            if not self.am_interested:
                if self.pieces & self.torrent.need_pieces:
                    self.am_interested = True
                    self.msg_queue.append(encode_msg('interested'))
                    print('Enq interested')
            elif not self.is_chocking and len(self.requests) < self.MAX_REQUESTS:
                new_request = self.torrent.get_next_request(self)
                if new_request:
                    index, begin, length = new_request
                    self.msg_queue.append(encode_msg('request', struct.pack('>III', index, begin, length)))
                    # update self.requests
                    self.requests.append((index, begin))
                    print('Enq request:', new_request)
                    # TODO: keep track of timeout, send KEEP_ALIVE messages as needed

    def send_msg(self):
        while self.msg_queue:
            try:
                self.sock.sendall(self.msg_queue[0])
            except socket.error:
                break
            self.msg_queue.popleft()


    def process_hander_handshakshake(self, handshake):
        # TODO: verify peer
        print ('Received handshake from', self.ip, handshake)
        # send h/sh as needed:
        if self.state == "waiting_to_send":
            self.msg_queue.append(self.torrent.handshake)
        #send bitfield
        self.msg_queue.append(encode_msg('bitfield', self.torrent.have_pieces.tobytes()))
        #update status
        self.state = "connected"
        print ("Connected to", self.ip)

    def process_msg(self, msg_str):
        msg = struct.unpack('B', msg_str[0])[0]
        print(MSG_TYPES[msg])
        # choke
        if msg == 0:
            self.is_chocking = True

        # unchoke
        elif msg == 1:
            self.is_chocking = False

        #interested
        elif msg == 2:
            #TODO: check number of outgoing connections before unchoking
            self.sock.sendall(encode_msg('unchoke'))

        #not interested
        elif msg == 3:
            self.is_interested = False
            #TODO: choke peer, decrement number of outgoing connections

        #peer has piece #x
        elif msg == 4:
            #update info about peer's need_pieces
            piece_idx = struct.unpack('>I', msg_str[1:])[0]
            self.pieces[piece_idx] = True

        #bitfield msg
        elif msg == 5:
            self.pieces = bitarray(bytes=msg_str[1:])
            del self.pieces[self.torrent.num_pieces:]  #cut out unnecessary bits

        #request for a piece
        elif msg == 6:
            #check that not choking
            if not self.am_choking:
                #locate requested piece, send it
                index, begin, length = struct.unpack('>I I I', msg_str[1:])
                #read the data
                data = self.torrent.read(index, begin, length)
                if data:  # if read is successful
                    self.msg_queue.append(encode_msg('piece', struct.pack('>I I', index, begin) + data))
                #update uploaded
                self.torrent.uploaded += length

        #piece
        elif msg == 7:
            index, begin = struct.unpack('>I I', msg_str[1:9])
            # store the file
            self.torrent.store(index, begin, msg_str[9:])
            #update the peer's queue
            self.requests.remove((index, begin))

        #cancel piece
        elif msg == 8:
            pass

        #port msg
        elif msg == 9:
            pass

        else:
            print('unknown message:', msg, msg_str)

    def teardown(self):
        for index, offset in self.requests:
            if self.torrent.need_blocks[index].count(1) == 0:
                self.torrent.need_pieces[index] = True
            self.torrent.need_blocks[index][offset / self.torrent.block_len] = True
        # reset values
        self.state = None
        self.am_interested = False
        self.is_chocking = True
        self.is_interested = False
        self.am_choking = True
        
        