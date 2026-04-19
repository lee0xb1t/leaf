package ctx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS = 0x980000DC
	SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT = 0x980000DD
	SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS   = 0x980000DC
)

const (
	AF_INET  = 2
	AF_INET6 = 23

	SOCKADDR_STORAGE_SIZE = 128

	REDIRECT_CONTEXT_SIZE = SOCKADDR_STORAGE_SIZE * 2
)

type SOCKADDR_STORAGE struct {
	Family uint16
	Data   [126]byte
}

type RedirectContext struct {
	Peer   *SockAddrInfo
	Origin *SockAddrInfo
}

type SockAddrInfo struct {
	IP   net.IP
	Port uint16
	Zone string
}

func QueryRedirectRecords(socket windows.Handle) ([]byte, error) {
	var bytesReturned uint32

	err := windows.WSAIoctl(
		socket,
		SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
		nil,
		0,
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	)

	if bytesReturned == 0 {
		return nil, nil
	}

	outBuffer := make([]byte, bytesReturned)
	err = windows.WSAIoctl(
		socket,
		SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
		nil,
		0,
		&outBuffer[0],
		uint32(len(outBuffer)),
		&bytesReturned,
		nil,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("WSAIoctl failed: %v", err)
	}

	return outBuffer[:bytesReturned], nil
}

func QueryRedirectContext(socket windows.Handle) ([]byte, error) {
	overlapped := &windows.Overlapped{}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent failed: %v", err)
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	bufSize := uint32(4096)
	outBuffer := make([]byte, bufSize)
	var bytesReturned uint32

	err = windows.WSAIoctl(
		socket,
		SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
		nil, 0,
		&outBuffer[0], bufSize,
		&bytesReturned,
		overlapped,
		0,
	)

	if err != nil {
		if err == windows.ERROR_IO_PENDING {
			_, err = windows.WaitForSingleObject(event, windows.INFINITE)
			if err != nil {
				return nil, fmt.Errorf("WaitForSingleObject failed: %v", err)
			}
			err = windows.GetOverlappedResult(socket, overlapped, &bytesReturned, false)
			if err != nil {
				return nil, fmt.Errorf("GetOverlappedResult failed: %v", err)
			}
		} else {
			return nil, fmt.Errorf("WSAIoctl failed: %v", err)
		}
	}

	return outBuffer[:bytesReturned], nil
}

func SetRedirectRecords(socket windows.Handle, records []byte) error {
	var bytesReturned uint32

	err := windows.WSAIoctl(
		socket,
		SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
		&records[0],
		uint32(len(records)),
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	)
	if err != nil {
		return fmt.Errorf("WSAIoctl failed: %v", err)
	}

	return nil
}

func ParseRedirectContext(contextData []byte) (*RedirectContext, error) {
	handleSize := unsafe.Sizeof(uintptr(0)) // 8 on 64-bit, 4 on 32-bit

	minSize := int(handleSize) + SOCKADDR_STORAGE_SIZE
	if len(contextData) < minSize {
		return nil, fmt.Errorf("context data too short: %d < %d", len(contextData), minSize)
	}

	if len(contextData) == 264 {
		handleSize = 8 // x64
	} else if len(contextData) == 260 {
		handleSize = 4 // x32
	}

	offset := int(handleSize)

	ctx := &RedirectContext{}

	// if handleSize == 8 {
	// 	processID := binary.LittleEndian.Uint64(contextData[0:8])
	// 	fmt.Printf("[DEBUG] Process ID: %d\n", processID)
	// } else {
	// 	processID := binary.LittleEndian.Uint32(contextData[0:4])
	// 	fmt.Printf("[DEBUG] Process ID: %d\n", processID)
	// }

	peerAddr, err := parseSockaddrStorage(contextData[offset : offset+SOCKADDR_STORAGE_SIZE])
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer address: %v", err)
	}
	ctx.Peer = peerAddr

	if len(contextData) >= offset+SOCKADDR_STORAGE_SIZE*2 {
		originAddr, err := parseSockaddrStorage(contextData[offset+SOCKADDR_STORAGE_SIZE : offset+SOCKADDR_STORAGE_SIZE*2])
		if err != nil {
			ctx.Origin = nil
		} else {
			ctx.Origin = originAddr
		}
	}

	return ctx, nil
}

func parseSockaddrStorage(data []byte) (*SockAddrInfo, error) {
	if len(data) < 2 {
		return nil, errors.New("data too short")
	}

	family := binary.LittleEndian.Uint16(data[0:2])

	switch family {
	case AF_INET:
		if len(data) < 16 {
			return nil, errors.New("incomplete IPv4 data")
		}
		return &SockAddrInfo{
			IP:   net.IPv4(data[4], data[5], data[6], data[7]),
			Port: binary.LittleEndian.Uint16(data[2:4]),
		}, nil

	case AF_INET6:
		if len(data) < 28 {
			return nil, errors.New("incomplete IPv6 data")
		}
		addr := &SockAddrInfo{
			IP:   make(net.IP, 16),
			Port: binary.LittleEndian.Uint16(data[2:4]),
		}
		copy(addr.IP, data[8:24])
		return addr, nil

	default:
		return nil, fmt.Errorf("unsupported address family: %d", family)
	}
}
