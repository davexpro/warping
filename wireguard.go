package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func genKey() {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(key.String())
}

func buildHandshakePacket(pri device.NoisePrivateKey, pub device.NoisePublicKey) []byte {
	d, _, err := netstack.CreateNetTUN([]netip.Addr{}, []netip.Addr{}, 1480)
	if err != nil {
		log.Fatalln("构建握手包失败: " + err.Error())
	}
	dev := device.NewDevice(d, conn.NewDefaultBind(), device.NewLogger(0, ""))

	dev.SetPrivateKey(pri)

	peer, err := dev.NewPeer(pub)
	if err != nil {
		log.Fatalln("构建握手包失败: " + err.Error())
	}
	msg, err := dev.CreateMessageInitiation(peer)
	if err != nil {
		log.Fatalln("构建握手包失败: " + err.Error())
	}

	var buf [device.MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()

	generator := device.CookieGenerator{}
	generator.Init(pub)
	generator.AddMacs(packet)
	return packet
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
