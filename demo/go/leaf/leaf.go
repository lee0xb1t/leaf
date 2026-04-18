package leaf

import (
	"encoding/binary"

	"golang.org/x/sys/windows"
)

const (
	FILE_DEVICE_UNKNOWN uint32 = 0x00000022

	// METHOD_BUFFERED = 0
	METHOD_BUFFERED uint32 = 0

	// FILE_ANY_ACCESS = 0
	FILE_ANY_ACCESS uint32 = 0
)

const (
	// #define IOCTL_PROXY_TCP_INIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x001, METHOD_BUFFERED, FILE_ANY_ACCESS)
	IOCTL_PROXY_TCP_INIT uint32 = 0x00220004

	// #define IOCTL_PROXY_TCP_SET_INCLUDED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x002, METHOD_BUFFERED, FILE_ANY_ACCESS)
	IOCTL_PROXY_TCP_SET_INCLUDED uint32 = 0x00220008

	// #define IOCTL_PROXY_TCP_SET_EXCLUDED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x003, METHOD_BUFFERED, FILE_ANY_ACCESS)
	IOCTL_PROXY_TCP_SET_EXCLUDED uint32 = 0x0022000C

	// #define IOCTL_PROXY_TCP_SET_PORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x004, METHOD_BUFFERED, FILE_ANY_ACCESS)
	IOCTL_PROXY_TCP_SET_PORT uint32 = 0x00220010

	// #define IOCTL_PROXY_TCP_ADD_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x005, METHOD_BUFFERED, FILE_ANY_ACCESS)
	IOCTL_PROXY_TCP_ADD_PROCESS uint32 = 0x00220014

	// #define IOCTL_PROXY_TCP_DESTROY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x006, METHOD_BUFFERED, FILE_ANY_ACCESS)
	IOCTL_PROXY_TCP_DESTROY uint32 = 0x00220018
)

func LeafInit() (windows.Handle, error) {
	fileHandle, err := windows.CreateFile(
		windows.StringToUTF16Ptr("\\\\.\\Leaf_NetFilter"),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	return fileHandle, err
}

func LeafDestroy(fileHandle windows.Handle) {
	if fileHandle != 0 {
		windows.Close(fileHandle)
	}
}

func LeafTcpInit(fileHandle windows.Handle) error {
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		fileHandle,
		IOCTL_PROXY_TCP_INIT,
		nil, 0,
		nil, 0,
		&bytesReturned,
		nil,
	)

	return err
}

func LeafTcpDestroy(fileHandle windows.Handle) error {
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		fileHandle,
		IOCTL_PROXY_TCP_DESTROY,
		nil, 0,
		nil, 0,
		&bytesReturned,
		nil,
	)

	return err
}

func LeafTcpSetIncluded(fileHandle windows.Handle) error {
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		fileHandle,
		IOCTL_PROXY_TCP_SET_INCLUDED,
		nil, 0,
		nil, 0,
		&bytesReturned,
		nil,
	)

	return err
}

func LeafTcpSetExcluded(fileHandle windows.Handle) error {
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		fileHandle,
		IOCTL_PROXY_TCP_SET_EXCLUDED,
		nil, 0,
		nil, 0,
		&bytesReturned,
		nil,
	)

	return err
}

func LeafTcpSetPort(fileHandle windows.Handle, port uint16) error {
	var bytesReturned uint32
	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, port)

	err := windows.DeviceIoControl(
		fileHandle,
		IOCTL_PROXY_TCP_SET_EXCLUDED,
		&portBytes[0], 2,
		nil, 0,
		&bytesReturned,
		nil,
	)

	return err
}

func LeafTcpAddProcess(fileHandle windows.Handle, pid windows.Handle) error {
	var bytesReturned uint32
	pidBytes := make([]byte, 2)
	binary.LittleEndian.PutUint64(pidBytes, uint64(pid))

	err := windows.DeviceIoControl(
		fileHandle,
		IOCTL_PROXY_TCP_SET_EXCLUDED,
		&pidBytes[0], 8,
		nil, 0,
		&bytesReturned,
		nil,
	)

	return err
}
