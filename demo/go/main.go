package main

import (
	"log"

	"github.com/txthinking/socks5"
	"golang.org/x/sys/windows"
	"lee0xb1t.com/leafsdk/leaf"
)

var (
	socks5Client *socks5.Client
	wsdData      windows.WSAData
	leafHandle   windows.Handle
)

func listen(port uint16) {
	version := uint32(0x0202)
	err := windows.WSAStartup(version, &wsdData)
	if err != nil {
		log.Panicf("[PROXY] WSAStartup start failed: %s\n", err)
	}
	defer windows.WSACleanup()

	listenSockHandle, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		log.Panicf("[PROXY] Create socket handle failed: %s\n", err)
	}
	defer windows.Close(listenSockHandle)

	sockAddr := &windows.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: 8888,
	}

	err = windows.Bind(listenSockHandle, sockAddr)
	if err != nil {
		log.Panicf("[PROXY] Socket bind error: %v", sockAddr)
	}
	log.Printf("[PROXY] Socket bind successful: %v", sockAddr)

	err = windows.Listen(listenSockHandle, windows.SOMAXCONN)
	if err != nil {
		log.Panicf("[PROXY] Socket listen error: %v", sockAddr)
	}
	log.Printf("[PROXY] Socket listen successful: %v", sockAddr)

	log.Printf("[PROXY] Start listening...")

	for {
		accpetHandle, fromSa, err := windows.Accept(listenSockHandle)
		if err != nil {
			log.Printf("[PROXY] Accpet error(ignored): %v", sockAddr)
			continue
		}

		go func() {
			log.Printf("[PROXY] Accpet new connection from: %v", fromSa)

			// TODO: read remote addr & set socks5 proxy
			//------------------------------
			socks5Conn, _ := socks5Client.Dial("tcp", "baidu.com:80")
			defer socks5Conn.Close()
			//------------------------------

			defer windows.Close(accpetHandle)

			// response := "HTTP/1.1 200 Connection Established\r\nProxy-Agent: LeafNetProxy\r\n"
			readBytes := make([]byte, 4096)
			writeBytes := make([]byte, 4096)

			for {
				n, err := windows.Read(accpetHandle, readBytes)
				if err != nil {
					break
				}

				if n > 0 {
					data := readBytes[:n]
					socks5Conn.Write(data)
				}
			}

			for {
				n, err := socks5Conn.Read(writeBytes)
				if err != nil {
					break
				}

				if n > 0 {
					data := writeBytes[:n]
					windows.Write(accpetHandle, data)
				}
			}

		}()
	}
}

func main() {
	var err error
	server := "127.0.0.1:53417"
	var port uint16 = 8888

	socks5Client, err = socks5.NewClient(server, "", "", 5000, 5000)
	if err != nil {
		log.Panicf("[PROXY] Socks5 server connect failed\n")
	}
	defer socks5Client.Close()

	go listen(port)

	leafHandle, err = leaf.LeafInit()
	if err != nil {
		log.Panicln("[PROXY] Leaf init failed")
	}
	defer leaf.LeafDestroy(leafHandle)

	err = leaf.LeafTcpInit(leafHandle)
	if err != nil {
		log.Panicln("[PROXY] Leaf tcp init failed")
	}
	defer leaf.LeafTcpDestroy(leafHandle)

	err = leaf.LeafTcpSetExcluded(leafHandle)
	if err != nil {
		log.Panicln("[PROXY] Leaf tcp set excluded flag failed")
	}

	err = leaf.LeafTcpSetPort(leafHandle, port)
	if err != nil {
		log.Panicf("[PROXY] Leaf tcp set port: %d failed\n", port)
	}
}
