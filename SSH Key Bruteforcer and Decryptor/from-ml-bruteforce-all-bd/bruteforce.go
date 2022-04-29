package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/pcap"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mode           = ""
	keyLen         = 16
	folderLocation = ""

	clientIp             = net.IPv4(192, 168, 11, 7)
	serverIp             = net.IPv4(192, 168, 12, 213)
	handle               *pcap.Handle
	err                  error
	serviceRequestPacket []byte
	iv                   []byte
	key                  []byte
	keyBlocks            []byte
	found                = false
)

func decrementIV(iv []byte) {
	for i := len(iv) - 1; i >= 0; i-- {
		iv[i]--
		if iv[i] != 0 {
			break
		}
	}
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

	cbc := cipher.NewCTR(block, iv)
	cbc.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func bruteforceKey(wg *sync.WaitGroup, potentialIV, packet []byte, size int, offset int) {
	defer wg.Done()
	//fmt.Println(fileName)
	//fmt.Println(hex.Dump(packet))
	i := offset
	for i < size {
		if found {
			break
		}
		potentialKey := keyBlocks[i : i+keyLen]

		//fmt.Printf("TEST IV : %s\n", hex.EncodeToString(potentialIV))
		//fmt.Printf("TEST KEY : %s\n", hex.EncodeToString(potentialKey))
		//fmt.Println("-------")

		//if len(potentialKey) != 16 {
		//	i += 8
		//	continue
		//}

		//if !strings.EqualFold(hex.EncodeToString(potentialKey), "dacb76e0853e034b9d73d9f6cb176fb5") {
		//	i += 8
		//	continue
		//}

		//fmt.Printf("POTENTIAL IV : %s\nKEY : %s\n", hex.EncodeToString(potentialIV), hex.EncodeToString(potentialKey))

		decrypted := []byte{}

		if mode == "ctr" {
			decrypted, _ = decryptCTR(potentialKey, potentialIV, packet)
			//if strings.EqualFold(hex.EncodeToString(potentialIV), "f7b67a7935682fd86a1cdd4d69c15b5c") && strings.EqualFold(hex.EncodeToString(potentialKey), "081d2b86838b82ab53646303febefbea") {
			//	fmt.Println(hex.Dump(decrypted))
			//}
		} else {
			decrypted, _ = decryptCBC(potentialKey, potentialIV, packet)
		}
		//fmt.Println(hex.Dump(decrypted))

		//SSH message no 5 -> client2server request, 6 -> server2client response
		//if int(decrypted[5]) == 6 {
		if int(decrypted[5]) == 6 {
			if strings.Contains(string(decrypted), "ssh-userauth") {
				iv = potentialIV
				key = potentialKey
				found = true
				break
			}
		}

		i += 8
	}
}

func readKeyFile(keyFile string) {
	bytes, err := ioutil.ReadFile(keyFile)
	string := string(bytes)
	string = strings.Replace(string, "\n", "", -1)
	keyBlocks, err = hex.DecodeString(string)
	if err != nil {
		panic(err)
	}
	//fmt.Println(hex.Dump(keyBlocks))
}

func readPcap(pcapFile string) {
	//load pcap file
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

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
			payload := tcpLayer.(*layers.TCP).LayerPayload()
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			src := ipv4Layer.(*layers.IPv4).SrcIP

			if len(payload) == 0 {
				continue
			}

			//let's convert the packet to string to get the protocol count
			payloadString := string(payload)
			if strings.Contains(payloadString, "SSH-2.0-OpenSSH") {
				protocolPacketCount++
				continue
			}

			if protocolPacketCount == 2 {
				if newKeyIsDone {
					//if packetNum == 58 {
					//	serviceRequestPacket = payload
					//	break
					//}
					if isServer2Client(src) {
						serviceRequestPacket = payload
						//fmt.Println(hex.Dump(serviceRequestPacket))
						break
					}
				}
				msgCodeI := int(payload[5])

				if msgCodeI == 21 {
					newKeyIsDone = true
					continue
				}
			}
		}
	}

	//fmt.Println("REQUEST SERVICE PACKET")
	//fmt.Println(hex.Dump(serviceRequestPacket))
}

func isServer2Client(src net.IP) bool {
	return src.Equal(serverIp)
}

func usage() {
	fmt.Printf("usage: %s [mode (ctr/cbc)] [location] [key length]\n", os.Args[0])
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
	folderLocation = args[1]
	keyLen, err = strconv.Atoi(args[2])
	if err != nil {
		usage()
	}

	mainStart := time.Now()

	err := filepath.Walk(folderLocation, func(path string, info fs.FileInfo, err error) error {

		if strings.Contains(path, "pcap") {
			//if !strings.Contains(path, "10484-1650982250") {
			//	return nil
			//}

			//fmt.Println(info.Name())
			keyFile := strings.Replace(path, info.Name(), "", -1) + strings.Split(info.Name(), ".pcap")[0] + ".txt"
			//fmt.Println(keyFile)

			//reset everything
			found = false //reset the found
			serviceRequestPacket = []byte{}
			iv = []byte{}
			key = []byte{}
			keyBlocks = []byte{}

			start := time.Now()
			readPcap(path)
			readKeyFile(keyFile)
			keySize := len(keyBlocks)

			gRoutineCount := 1

			i := 0
			for i < keySize {

				var wg sync.WaitGroup

				increment := gRoutineCount * 8

				x := 0
				for x < gRoutineCount {
					wg.Add(1)
					from := i + (16 * x)
					to := i + (16 * (x + 1))
					potentialIV := keyBlocks[from:to]
					//go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, to)

					//for key B and D, we have do decrement the key by 2
					//decrementIV(potentialIV)
					//decrementIV(potentialIV)
					go bruteforceKey(&wg, potentialIV, serviceRequestPacket, keySize, 0)
					x++
				}

				wg.Wait()

				//potentialIV := cleanHeap[i : i+16]
				//bruteforceKey(potentialIV, serviceRequestPacket, cleanHeapSize)

				if found {
					elapsed := time.Since(start).Seconds()
					//fmt.Printf("IV : %s\n", hex.EncodeToString(iv))
					//fmt.Printf("KEY : %s\n", hex.EncodeToString(key))
					fmt.Printf("%s : %t : %fs\n", info.Name(), found, elapsed)

					wg.Wait()
					break
				}

				i += increment
			}
			if !found {
				fmt.Printf("%s not found\n", info.Name())
			}

		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	mainElapsed := time.Since(mainStart).Seconds()
	fmt.Printf("In Total : %fs\n", mainElapsed)

	//start := time.Now()
	//readPcap()
	//readHeap()
	//fmt.Printf("Size before cleanup : %d\n", len(heap))
	////cleanupHeap()
	//cleanupHeapHamming()
	//cleanHeapSize := len(cleanHeap)
	//fmt.Printf("Size after cleanup : %d\n", cleanHeapSize)
	//
	////let's brute force
	//pbar := pb.StartNew(cleanHeapSize)
	//i := 0
	//
	//gRoutineCount := 5
	//
	//for i < cleanHeapSize {
	//
	//	var wg sync.WaitGroup
	//
	//	increment := gRoutineCount * 8
	//
	//	pbar.Add(increment)
	//
	//	x := 0
	//	for x < gRoutineCount {
	//		wg.Add(1)
	//		from := i + (16 * x)
	//		to := i + (16 * (x + 1))
	//		potentialIV := cleanHeap[from:to]
	//		//go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, to)
	//		go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, 0)
	//		x++
	//	}
	//
	//	wg.Wait()
	//
	//	//potentialIV := cleanHeap[i : i+16]
	//	//bruteforceKey(potentialIV, serviceRequestPacket, cleanHeapSize)
	//
	//	if found {
	//		break
	//	}
	//
	//	i += increment
	//}
	//elapsed := time.Since(start).Seconds()
	//pbar.Finish()
	//
	//fmt.Printf("IV : %s\n", hex.EncodeToString(iv))
	//fmt.Printf("KEY : %s\n", hex.EncodeToString(key))
	//log.Printf("It took : %fs\n", elapsed)
}
