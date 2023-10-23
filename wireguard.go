package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/netip"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func buildHandshakePacket(pri device.NoisePrivateKey, pub device.NoisePublicKey) ([]byte, error) {
	d, _, err := netstack.CreateNetTUN([]netip.Addr{}, []netip.Addr{}, 1480)
	if err != nil {
		return nil, err
	}

	dev := device.NewDevice(d, conn.NewDefaultBind(), device.NewLogger(0, ""))
	dev.SetPrivateKey(pri)

	peer, err := dev.NewPeer(pub)
	if err != nil {
		return nil, err
	}
	msg, err := dev.CreateMessageInitiation(peer)
	if err != nil {
		return nil, err
	}

	var buf [device.MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	pkt := writer.Bytes()

	gen := device.CookieGenerator{}
	gen.Init(pub)
	gen.AddMacs(pkt)
	return pkt, nil
}

func getNoisePrivateKeyFromBase64(b string) (device.NoisePrivateKey, error) {
	pk := device.NoisePrivateKey{}
	h, err := encodeBase64ToHex(b)
	if err != nil {
		return pk, err
	}
	pk.FromHex(h)
	return pk, nil
}

func getNoisePublicKeyFromBase64(b string) (device.NoisePublicKey, error) {
	pk := device.NoisePublicKey{}
	h, err := encodeBase64ToHex(b)
	if err != nil {
		return pk, err
	}
	pk.FromHex(h)
	return pk, nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}
