package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	mode     = ""
	pcapFile = ""
	logFile  = ""

	clientIp            = net.IPv4(192, 168, 11, 7)
	serverIp            = net.IPv4(192, 168, 12, 213)
	handle              *pcap.Handle
	err                 error
	serviceResponseDone = false
)

type SSHKeysLog struct {
	KeyA string `json:"KEY_A"`
	KeyB string `json:"KEY_B"`
	KeyC string `json:"KEY_C"`
	KeyD string `json:"KEY_D"`
}

func decryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		fmt.Printf("ciphertext too short")
		return nil, nil
	}

	var plaintext = make([]byte, len(ciphertext))

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(plaintext, ciphertext)

	//plaintext = ciphertext

	return plaintext, nil
}

func decryptCTR(key, iv, ciphertext []byte) ([]byte, error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		fmt.Printf("ciphertext too short")
		return nil, nil
	}

	var plaintext = make([]byte, len(ciphertext))

	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func decryptChaCha(keya, ciphertexta []byte) ([]byte, error) {
	//TODO
	return nil, nil
}

func decryptGCM(key, iv, ciphertext []byte) ([]byte, error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		fmt.Printf("ciphertext too short")
		return nil, nil
	}

	aesgcm, _ := cipher.NewGCM(block)

	a, err := aesgcm.Open(nil, iv, ciphertext, nil)
	i := 100
	for err != nil {

		decrementIV(iv)
		fmt.Printf("Trying IV : %s\n", hex.EncodeToString(iv))
		a, err = aesgcm.Open(nil, iv, ciphertext, nil)
		fmt.Println(err.Error())
		i--
		if i == 0 {
			panic("Nope!")
		}
	}

	return a, err
}

func digestPacket(plaintext []byte) (msgCode int) {
	pktLenHex := hex.EncodeToString(plaintext[0:4])
	pktLen, _ := strconv.ParseInt(pktLenHex, 16, 64)
	fmt.Printf("PKT LEN : %d\n", pktLen)
	msgCode = int(plaintext[5])
	fmt.Printf("MSG CODE INT : %d\n", msgCode)
	return
}

func isServer2Client(src net.IP) bool {
	return src.Equal(serverIp)
}

func incrementIV(iv []byte) {
	add := byte(1)
	x := byte(1)
	for i := len(iv) - 1; i >= 0; i-- {
		iv[i] += add
		x = iv[i]
		x = (x | (x >> 4)) & 0xf
		x = (x | (x >> 2)) & 0x3
		x = (x | (x >> 1)) & 0x1
		add *= (x ^ 1)

		//if iv[i] != 0 {
		//	break
		//}
	}
}

func decrementIV(iv []byte) {
	for i := len(iv) - 1; i >= 0; i-- {
		iv[i]--
		if iv[i] != 0 {
			break
		}
	}
}

func checkIV(key, iv, payload []byte, strToFind string, server2client bool) []byte {
	fmt.Println("Let's try the IV")

	round := 0
	var ivCopy = make([]byte, len(iv))
	copy(ivCopy, iv)

	fmt.Println("Increment")
	for round < 100 {
		var payloadCopy = make([]byte, len(payload))
		copy(payloadCopy, payload)
		payloadCopy, _ = decryptCTR(key, ivCopy, payload)
		if strings.Contains(string(payloadCopy), "ssh-userauth") {
			if server2client {
				fmt.Printf("Found the IV for server2client: %s\n", hex.EncodeToString(ivCopy))
			} else {
				fmt.Printf("Found the IV for client2server: %s\n", hex.EncodeToString(ivCopy))
			}
			return ivCopy
		} else {
			incrementIV(ivCopy)
		}
		round++
	}

	round = 0
	copy(ivCopy, iv)
	fmt.Println("Decrement")
	for round < 100 {
		var payloadCopy = make([]byte, len(payload))
		copy(payloadCopy, payload)
		payloadCopy, _ = decryptCTR(key, ivCopy, payload)
		if strings.Contains(string(payloadCopy), strToFind) {
			if server2client {
				fmt.Printf("Found the IV for server2client: %s\n", hex.EncodeToString(ivCopy))
			} else {
				fmt.Printf("Found the IV for client2server: %s\n", hex.EncodeToString(ivCopy))
			}
			return ivCopy
		} else {
			decrementIV(ivCopy)
		}
		round++
	}

	panic("IV not found")
}

func usage() {
	fmt.Printf("usage: %s [mode (ctr/cbc)] [pcap file] [log file]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 3 {
		usage()
	}

	mode = args[0]
	pcapFile = args[1]
	logFile = args[2]

	//setup color
	red := color.New(color.FgRed)
	blue := color.New(color.FgBlue)
	yellow := color.New(color.FgYellow)

	//load json file
	jsonFile, err := os.Open(logFile)
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	//load pcap file
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// load json value
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var sshkeyslog SSHKeysLog
	err = json.Unmarshal(byteValue, &sshkeyslog)
	if err != nil {
		log.Fatal(err)
		return
	}

	// store the IVs and Keys
	IV_client2server, _ := hex.DecodeString(sshkeyslog.KeyA)
	KEY_client2server, _ := hex.DecodeString(sshkeyslog.KeyC)
	IV_server2client, _ := hex.DecodeString(sshkeyslog.KeyB)
	KEY_server2client, _ := hex.DecodeString(sshkeyslog.KeyD)

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//https://golang.hotexamples.com/examples/github.com.google.gopacket/-/Payload/golang-payload-function-examples.html
	var packetNum = 0
	var protocolPacketCount = 0
	var newKeyIsDone = false
	for packet := range packetSource.Packets() {

		packetNum++

		//fmt.Println(packet)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			_, _ = red.Printf("\n\n=================== Packet #%d ===================\n", packetNum)
			payload := tcpLayer.(*layers.TCP).LayerPayload()
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			src := ipv4Layer.(*layers.IPv4).SrcIP
			//dst := ipv4Layer.(*layers.IPv4).DstIP

			server2client := isServer2Client(src)

			var key []byte
			var iv []byte

			if server2client {
				_, _ = blue.Println("SERVER 2 CLIENT")
				key = KEY_server2client
				iv = IV_server2client
			} else {
				_, _ = blue.Println("CLIENT 2 SERVER")
				key = KEY_client2server
				iv = IV_client2server
			}

			if len(payload) == 0 {

				if mode == "ctr" {
					if newKeyIsDone {
						incrementIV(iv)
					}
				}

				fmt.Println("EMPTY PACKET")
				continue
			}

			_, _ = yellow.Println(hex.Dump(payload))

			//let's convert the packet to string to get the protocol count
			payloadString := string(payload)
			if strings.Contains(payloadString, "SSH-2.0-OpenSSH") {
				protocolPacketCount++
				continue
			}

			if protocolPacketCount == 2 {
				if newKeyIsDone {

					fmt.Println("THIS PACKET IS ENCRYPTED -- DECRYPTED:")
					fmt.Printf("IV : %s\n", hex.EncodeToString(iv))
					fmt.Printf("KEY : %s\n", hex.EncodeToString(key))
					if strings.EqualFold(mode, "ctr") {

						if !server2client && !serviceResponseDone {
							fmt.Println("HERE!")
							iv = checkIV(key, iv, payload, "ssh-userauth", server2client)
							IV_client2server = iv
						}

						//first packet after the new key is client2server request for service, the IV can be use the first one
						//we need to naive-single-bruteforce the IV of the server though
						if server2client && !serviceResponseDone {
							iv = checkIV(key, iv, payload, "ssh-userauth", server2client)
							IV_server2client = iv
							serviceResponseDone = true
						}

						payload, _ = decryptCTR(key, iv, payload)
						fmt.Println(hex.Dump(payload))
						digestPacket(payload)

						incrementIV(iv)

					} else if strings.EqualFold(mode, "cbc") {
						payload, _ = decryptCBC(key, iv, payload)
						fmt.Println(hex.Dump(payload))
						digestPacket(payload)
					} else if strings.EqualFold(mode, "chacha") {
						payload, err = decryptChaCha(key, payload)
						if err != nil {
							panic(err)
						}
						fmt.Println(hex.Dump(payload))
						digestPacket(payload)
					} else if strings.EqualFold(mode, "gcm") {
						payload, err = decryptGCM(key, iv, payload)
						if err != nil {
							panic(err)
						}
						fmt.Println(hex.Dump(payload))
					}

				} else {
					msgCode := digestPacket(payload)
					if msgCode == 21 {
						fmt.Println("NEW KEY IS DONE")
						newKeyIsDone = true
						continue
					}
				}
			}

			//fmt.Println(data)
		}
	}
}
