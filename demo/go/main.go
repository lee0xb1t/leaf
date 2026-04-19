package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/txthinking/socks5"
	"golang.org/x/sys/windows"
	"lee0xb1t.com/leafsdk/ctx"
	"lee0xb1t.com/leafsdk/leaf"
)

const (
	SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS = 0x980000DC
	SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT = 0x980000DD
)

var (
	socks5Client *socks5.Client
	leafHandle   windows.Handle

	wg sync.WaitGroup
)

func listen(port uint16) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go func() {
			defer c.Close()

			clientAddr := c.RemoteAddr().(*net.TCPAddr)
			clientIP := clientAddr.IP
			clientPort := uint16(clientAddr.Port)

			tcpConn, ok := c.(*net.TCPConn)
			if !ok {
				return
			}
			f, err := tcpConn.File()
			if err != nil {
				return
			}
			defer f.Close()

			sockHandle := windows.Handle(f.Fd())

			//------------------------------
			bytesContext, err := ctx.QueryRedirectContext(sockHandle)
			if err != nil {
				log.Fatalln("[PROXY] failed to query redirect context:", err)
			}
			redirectContext, err := ctx.ParseRedirectContext(bytesContext)
			if err != nil {
				log.Fatalln("[PROXY] failed to parse redirect context:", err)
			}

			targetAddr := fmt.Sprintf("%s:%d", redirectContext.Peer.IP.String(), redirectContext.Peer.Port)

			//------------------------------
			socks5Conn, err := socks5Client.Dial("tcp", targetAddr)
			if err != nil {
				log.Printf("[PROXY] SOCKS5 dial failed: %v", err)
				return
			}
			log.Printf("[PROXY] Connect to socks5 server and proxy %s\n", fmt.Sprintf("%s:%d", redirectContext.Peer.IP.String(), redirectContext.Peer.Port))
			defer socks5Conn.Close()
			//------------------------------

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				_, err := io.Copy(socks5Conn, c)
				if err != nil && err != io.EOF {
					log.Printf("[PROXY] Client -> Target error: %v", err)
				}
				if tcpConn, ok := socks5Conn.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			go func() {
				defer wg.Done()
				_, err := io.Copy(c, socks5Conn)
				if err != nil && err != io.EOF {
					log.Printf("[PROXY] Target -> Client error: %v", err)
				}
				if tcpConn, ok := c.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			wg.Wait()

			log.Printf("[PROXY] Tunnel closed: %s:%d", clientIP, clientPort)
		}()
	}
}

func main() {
	var err error
	server := "192.168.110.1:10801"
	var port uint16 = 8888

	wg.Add(1)

	socks5Client, err = socks5.NewClient(server, "", "", 5000, 5000)
	if err != nil {
		log.Panicf("[PROXY] Socks5 server connect failed\n")
	}
	defer socks5Client.Close()

	go listen(port)

	leafHandle, err = leaf.LeafInit()
	if err != nil {
		log.Panicln("[PROXY] Leaf init failed:", err)
	}
	defer leaf.LeafDestroy(leafHandle)

	err = leaf.LeafTcpInit(leafHandle)
	if err != nil {
		log.Panicln("[PROXY] Leaf tcp init failed:", err)
	}
	defer leaf.LeafTcpDestroy(leafHandle)

	err = leaf.LeafTcpSetExcluded(leafHandle)
	if err != nil {
		log.Panicln("[PROXY] Leaf tcp set excluded flag failed:", err)
	}

	err = leaf.LeafTcpSetPort(leafHandle, port)
	if err != nil {
		log.Panicf("[PROXY] Leaf tcp set port: %d failed: %s\n", port, err)
	}

	wg.Wait()
}
