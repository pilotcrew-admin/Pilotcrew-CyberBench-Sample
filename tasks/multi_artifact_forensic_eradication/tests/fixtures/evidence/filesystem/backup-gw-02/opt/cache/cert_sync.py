#!/usr/bin/python3
import socket,time
while True:
    try:
        s=socket.create_connection(("203.0.113.201",443),5)
        s.sendall(b"sync")
        s.close()
    except OSError:
        pass
    time.sleep(300)
