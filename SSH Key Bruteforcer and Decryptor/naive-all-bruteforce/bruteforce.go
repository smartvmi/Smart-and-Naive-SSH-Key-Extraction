package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mode           = "ctr"
	keyLen         = 16
	folderLocation = ""

	clientIp             = net.IPv4(192, 168, 11, 7)
	serverIp             = net.IPv4(192, 168, 12, 213)
	handle               *pcap.Handle
	err                  error
	serviceRequestPacket []byte
	heap                 []byte
	cleanHeap            []byte
	iv                   []byte
	key                  []byte
	found                = false
)

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

	i := offset
	for i < size {
		if found {
			break
		}
		potentialKey := cleanHeap[i : i+keyLen]

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
		} else {
			decrypted, _ = decryptCBC(potentialKey, potentialIV, packet)
		}
		//fmt.Println(hex.Dump(decrypted))

		//SSH message no 5 -> client2server request, 6 -> server2client response
		//if int(decrypted[5]) == 6 {
		if int(decrypted[5]) == 5 {
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

func readHeap(heapFile string) {
	heap, err = ioutil.ReadFile(heapFile)
	if err != nil {
		panic(err)
	}
	//fmt.Println(hex.Dump(heap))
}

func cleanupHeap() {
	size := len(heap)
	zeroes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	i := 0
	for i < size {
		eightBytes := heap[i : i+8]

		if bytes.Compare(eightBytes, zeroes) != 0 {
			cleanHeap = append(cleanHeap, eightBytes...)
		}

		//weight := bits.OnesCount64(binary.LittleEndian.Uint64(eightBytes))
		//if (weight > 32-keyLen) && (weight < 32+keyLen) {
		//	cleanHeap = append(cleanHeap, eightBytes...)
		//}
		i += 8
	}
	//fmt.Println(hex.Dump(cleanHeap))
}

func cleanupHeapHamming() {
	size := len(heap)
	i := 0
	for i < size {
		eightBytes := heap[i : i+8]

		weight := bits.OnesCount64(binary.LittleEndian.Uint64(eightBytes))
		if (weight > 32-keyLen) && (weight < 32+keyLen) {
			cleanHeap = append(cleanHeap, eightBytes...)
		}
		i += 8
	}
	//fmt.Println(hex.Dump(cleanHeap))
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
					if !isServer2Client(src) {
						serviceRequestPacket = payload
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
			//fmt.Println(info.Name())
			dumpFile := strings.Replace(path, info.Name(), "", -1) + strings.Split(info.Name(), ".pcap")[0] + "-heap.raw"
			//fmt.Println(info.Name())

			//reset everything
			found = false //reset the found
			serviceRequestPacket = []byte{}
			heap = []byte{}
			cleanHeap = []byte{}
			iv = []byte{}
			key = []byte{}

			start := time.Now()
			readPcap(path)
			readHeap(dumpFile)
			cleanupHeapHamming()
			cleanHeapSize := len(cleanHeap)

			gRoutineCount := 5

			i := 0
			for i < cleanHeapSize {

				var wg sync.WaitGroup

				increment := gRoutineCount * 8

				x := 0
				for x < gRoutineCount {
					wg.Add(1)
					from := i + (16 * x)
					to := i + (16 * (x + 1))
					potentialIV := cleanHeap[from:to]
					//go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, to)
					go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, to)
					x++
				}

				wg.Wait()

				//potentialIV := cleanHeap[i : i+16]
				//bruteforceKey(potentialIV, serviceRequestPacket, cleanHeapSize)

				if found {
					elapsed := time.Since(start).Seconds()
					//fmt.Printf("IV : %s\n", hex.EncodeToString(iv))
					//fmt.Printf("KEY : %s\n", hex.EncodeToString(key))
					fmt.Printf("%s : %fs\n", info.Name(), elapsed)

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
}
