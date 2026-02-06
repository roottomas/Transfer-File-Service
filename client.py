import socket
import sys
import pickle
import os
import struct

# Constants
BLOCK_SIZE = 512
OP_DAT = 1   # data packet
OP_ACK = 2   # acknowledgment
OP_ERR = 3   # error message
OP_RRQ = 4   # read request (dir or get)

def send_packet(sock, packet):
    """
    Serialize (pickle) the packet, prepend a 4-byte length header,
    and send it over the TCP socket.
    """
    data = pickle.dumps(packet)                  # turn python object into bytes
    length = struct.pack("!I", len(data))        # 4-byte big-endian integer (message length)
    sock.sendall(length + data)                  # send [length prefix][data]

def receive_packet(sock):
    """
    Read one complete packet from the socket
    1. First read 4 bytes (the length prefix)
    2. Then read exactly <length> bytes
    3. Unpickle and return the object
    """
    # read 4-byte header 
    length_buf = b""
    while len(length_buf) < 4:
        more = sock.recv(4 - len(length_buf))
        if not more:
            return None
        length_buf += more
    length = struct.unpack("!I", length_buf)[0]  # decode 4 bytes into integer

    # read payload 
    data_buf = b""
    while len(data_buf) < length:
        more = sock.recv(length - len(data_buf))
        if not more:
            return None
        data_buf += more

    return pickle.loads(data_buf)  # turn bytes into python object

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 client.py <server_addr> <server_port>")
        return

    server_addr = sys.argv[1]
    port = int(sys.argv[2])

    # connect to server 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_addr, port))
        print("Connect to server")
    except Exception as e:
        print("Unable to connect with the server:", e)
        return

    # handshake: receive greeting and send ACK 
    pkt = receive_packet(sock)
    if pkt and pkt.get("op") == OP_DAT:
        print(pkt["data"])  # server greeting
        send_packet(sock, {"op": OP_ACK, "block": 0})
    else:
        print("Protocol error")
        sock.close()
        return

    # command loop
    while True:
        cmd = input("client> ").strip().split()
        if not cmd:
            continue

        if cmd[0] == "dir":
            # Ask server for dir (filename="")
            send_packet(sock, {"op": OP_RRQ, "filename": ""})
            while True:
                pkt = receive_packet(sock)
                if not pkt or pkt.get("op") != OP_DAT:
                    break
                if pkt["data"] == "":  # empty block, means end of listing
                    break
                print(pkt["data"])

        elif cmd[0] == "get":
            if len(cmd) != 3:
                print("Usage: get <remote_filename> <local_filename>")
                continue
            remote, local = cmd[1], cmd[2]
            if os.path.exists(local): # Check if the file we're asking for already exists
                print("File already exists locally")
                continue

            send_packet(sock, {"op": OP_RRQ, "filename": remote})
            with open(local, "wb") as f:
                while True:
                    pkt = receive_packet(sock)
                    if not pkt:
                        print("Transfer aborted")
                        break
                    if pkt.get("op") == OP_ERR:
                        print(pkt["msg"])
                        os.remove(local)  # remove incomplete file
                        break
                    if pkt["op"] != OP_DAT:
                        print("Protocol error")
                        break
                    data = pkt["data"]
                    f.write(data)
                    if len(data) < BLOCK_SIZE:  # last block is smaller than 512
                        print("File transfer completed")
                        break

        elif cmd[0] == "end":
            # Tell server to close, then exit
            send_packet(sock, {"op": "END"})
            print("Connection close, client ended")
            sock.close()
            break

        else:
            print("Unknown command")

if __name__ == "__main__":
    main()

