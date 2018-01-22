//build +windows
package adapter

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/arcpop/govpn/core"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	fileDeviceUnknown = uint32(0x00000022)
	componentID       = "tap0901"
)

var (
	ErrAdapterNotFound       = errors.New("adapter: device not found")
	ErrInterfaceNameNotFound = errors.New("adapter: name of interface not found")

	ioctlGetMacAddress  = ctlCode(fileDeviceUnknown, 1, 0, 0)
	ioctlSetMediaStatus = ctlCode(fileDeviceUnknown, 6, 0, 0)
)

type tapAdapter struct {
	name         string
	driverHandle windows.Handle

	receiveChannel, sendChannel chan []byte

	mtu     int
	macAddr core.MacAddr

	originalMTU string
	regKey      registry.Key
}

func newTAP(name string, mtu, queueSize int) (Instance, error) {
	key, err := getTAPAdapterRegistryKey(componentID)
	if err != nil {
		return nil, err
	}

	deviceID, err := getDeviceID(key)
	if err != nil {
		return nil, err
	}
	instance := &tapAdapter{
		regKey:         key,
		receiveChannel: make(chan []byte, queueSize),
		sendChannel:    make(chan []byte, queueSize),
	}
	/*
		instance.originalMTU, err = getMTU(key)
		if err != nil {
			return nil, err
		}

		instance.mtu = mtu
		err = setMTU(key, strconv.Itoa(mtu))
		if err != nil {
			return nil, err
		}
	*/
	path, err := windows.UTF16PtrFromString(`\\.\Global\` + deviceID + `.tap`)
	if err != nil {
		instance.Close()
		return nil, err
	}

	instance.driverHandle, err = windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		instance.Close()
		return nil, err
	}
	err = setMediaStatus(instance.driverHandle, true)
	if err != nil {
		instance.Close()
		return nil, err
	}
	macAddr, err := getMacAddr(instance.driverHandle)
	if err != nil {
		instance.Close()
		return nil, err
	}
	copy(instance.macAddr[:], macAddr[:])
	instance.name, err = getAdapterName(macAddr)
	if err != nil {
		instance.Close()
		return nil, err
	}

	go instance.readWorker()
	go instance.writeWorker()

	return instance, nil
}
func (a *tapAdapter) readWorker() {
	for {
		pkt := make([]byte, 1700)
		n, err := windows.Read(a.driverHandle, pkt)
		if err != nil {
			log.Println("adapter: read returned error: " + err.Error())
			return
		}
		pkt = pkt[:n]
		a.receiveChannel <- pkt
	}
}
func (a *tapAdapter) writeWorker() {
	for pkt, ok := <-a.sendChannel; ok; pkt, ok = <-a.sendChannel {
		_, err := windows.Write(a.driverHandle, pkt)
		if err != nil {
			log.Println("adapter: write returned error: " + err.Error())
		}
	}
}
func (a *tapAdapter) TransmitChannel() chan<- []byte {
	return a.sendChannel
}

func (a *tapAdapter) ReceiveChannel() <-chan []byte {
	return a.receiveChannel
}

func (a *tapAdapter) GetName() string {
	return a.name
}

func (a *tapAdapter) GetMTU() int {
	return a.mtu
}

func (a *tapAdapter) GetMACAddress() *core.MacAddr {
	var m core.MacAddr
	copy(m[:], a.macAddr[:])
	return &m
}

func (a *tapAdapter) Close() error {
	close(a.sendChannel)
	if a.driverHandle != 0 {
		setMediaStatus(a.driverHandle, false)
		windows.Close(a.driverHandle)
	}
	if a.regKey != 0 {
		if a.originalMTU != "" {
			a.regKey.SetStringValue("MTU", a.originalMTU)
		}
		a.regKey.Close()
	}
	return nil
}

func getAdapterName(addr *core.MacAddr) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		if bytes.Compare(i.HardwareAddr, addr[:]) == 0 {
			return i.Name, nil
		}
	}
	return "", ErrInterfaceNameNotFound
}

func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

func setMediaStatus(h windows.Handle, connected bool) error {
	var mediaStatus [4]byte
	var retVal uint32
	if connected {
		mediaStatus[0] = 1
	}
	err := windows.DeviceIoControl(
		h,
		ioctlSetMediaStatus,
		&mediaStatus[0],
		4,
		&mediaStatus[0],
		4,
		&retVal,
		nil,
	)
	if err == nil {
		return nil
	}
	return fmt.Errorf("adapter: DeviceIoControl ioctl SetMediaStatus failed with error \"%s\"", err.Error())
}
func getMacAddr(h windows.Handle) (*core.MacAddr, error) {
	var macAddr core.MacAddr
	var retVal uint32
	err := windows.DeviceIoControl(
		h,
		ioctlGetMacAddress,
		&macAddr[0],
		6,
		&macAddr[0],
		6,
		&retVal,
		nil,
	)
	if err == nil {
		return &macAddr, nil
	}
	return nil, fmt.Errorf("adapter: DeviceIoControl ioctl GetMacAddress failed with error \"%s\"", err.Error())
}

func getDeviceID(key registry.Key) (string, error) {
	val, _, err := key.GetStringValue("NetCfgInstanceId")
	if err != nil {
		return "", err
	}
	return val, nil
}

func setMTU(key registry.Key, mtu string) error {
	return key.SetStringValue("MTU", mtu)
}

func getMTU(key registry.Key) (string, error) {
	v, _, err := key.GetStringValue("MTU")
	return v, err
}

func getTAPAdapterRegistryKey(componentID string) (registry.Key, error) {
	regkey := `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regkey, registry.READ)
	if err != nil {
		return 0, err
	}
	defer k.Close()

	keys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return 0, err
	}

	for _, v := range keys {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, regkey+"\\"+v, registry.READ)
		if err != nil {
			continue
		}

		val, _, err := key.GetStringValue("ComponentId")
		if err != nil {
			key.Close()
			continue
		}

		if val == componentID {
			return key, nil
		}
		key.Close()
	}
	return 0, ErrAdapterNotFound
}
