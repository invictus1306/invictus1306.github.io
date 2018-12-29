from socket import *

host = "127.0.0.1"
port = 80

def run():
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((host, port))
    header = " HTTP/\r\n x-sessioncookie: BBBB\r\nAccept: AAAA\r\n\r\n"
    s.send(header)

if __name__ == '__main__':
    run()
