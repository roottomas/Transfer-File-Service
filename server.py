import socket
import threading
import os
import pickle
import sys
import struct

BLOCK_SIZE = 512

# Opcodes (same as client)
OP_DAT = 1   # data
OP_ACK = 2   # acknowledgment
OP_ERR = 3   # error
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

def handle_client(conn, addr, base_dir):
    """
    Each client runs in its own thread.
    Supports: greeting, dir listing, file transfer, end command
    """
    try:
        # send greeting 
        greeting = {"op": OP_DAT, "block": 0, "data": f"Welcome to {addr[0]} file server"}
        send_packet(conn, greeting)

        # wait for ACK 
        pkt = receive_packet(conn)
        if not pkt or pkt.get("op") != OP_ACK:
            conn.close()
            return

        # main loop 
        while True:
            pkt = receive_packet(conn)
            if not pkt:
                break

            op = pkt.get("op")
            if op == OP_RRQ:
                filename = pkt.get("filename", "")
                if filename == "":
                    # Dir request
                    files = os.listdir(base_dir)
                    block = 1
                    for f in files:
                        send_packet(conn, {"op": OP_DAT, "block": block, "data": f})
                        block += 1
                    # End of listing, so we send an empty block
                    send_packet(conn, {"op": OP_DAT, "block": block, "data": ""})

                else:
                    # Get request
                    path = os.path.join(base_dir, filename)
                    if not os.path.exists(path):
                        send_packet(conn, {"op": OP_ERR, "msg": "File not found"})
                        continue

                    with open(path, "rb") as f:
                        block = 1
                        while True:
                            chunk = f.read(BLOCK_SIZE)
                            send_packet(conn, {"op": OP_DAT, "block": block, "data": chunk})
                            if len(chunk) < BLOCK_SIZE:
                                break
                            block += 1

            elif op == "END":
                break

            else:
                # Any other unexpected opcode means protocol error
                send_packet(conn, {"op": OP_ERR, "msg": "Protocol error"})

    finally:
        conn.close()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <port>")
        return

    port = int(sys.argv[1])
    base_dir = os.getcwd()  # directory where the server files live

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("", port))
        server.listen(5)
        print("Server is running")
    except Exception as e:
        print("Unable to start server:", e)
        return

    # keep accepting clients
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, base_dir))
        t.start()

if __name__ == "__main__":
    main()

