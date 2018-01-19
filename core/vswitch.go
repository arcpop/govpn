package core

import (
	"log"
	"sync"
)

type vSwitch struct {
	sync.RWMutex
	associatedClients map[MacAddr]*Endpoint
}

func (v *vSwitch) OnClientDisconnect(c *Endpoint) {
	toDelete := make([]MacAddr, 0, 5)
	v.Lock()
	for k, v := range v.associatedClients {
		if v == c {
			toDelete = append(toDelete, k)
		}
	}
	for _, k := range toDelete {
		delete(v.associatedClients, k)
	}
	v.Unlock()
}

func (v *vSwitch) SwitchPacket(s *Server, p []byte) {
	var destAddr MacAddr
	copy(destAddr[:], p[0:6])

	if destAddr == s.ServerMACAddress {
		s.serverReceiveQueue <- p
		return
	}

	if destAddr == MACBroadcastAddr {
		s.serverReceiveQueue <- p
		s.sendPacketToAllClients(p)
		return
	}
	v.RLock()
	to, ok := v.associatedClients[destAddr]
	v.RUnlock()
	if ok {
		pkt, err := encryptVPNPacket(p, to.cipherContext, false)
		if err != nil {
			log.Println("core: server: failed to encrypt packet: " + err.Error())
			return
		}
		s.packetQueue <- &QueuedPacket{
			Addr: to.udpAddress,
			Data: pkt,
		}
		return
	}
	s.sendPacketToAllClients(p)
}

func (v *vSwitch) SwitchPacketFromClient(s *Server, p []byte, from *Endpoint) {
	var sourceAddr MacAddr
	copy(sourceAddr[:], p[6:12])

	if sourceAddr != MACBroadcastAddr {
		v.Lock()
		v.associatedClients[sourceAddr] = from
		v.Unlock()
	}
	v.SwitchPacket(s, p)
}
