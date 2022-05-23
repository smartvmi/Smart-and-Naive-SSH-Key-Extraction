package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/pcap"
	"io/ioutil"
	"log"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	mode     = ""
	keyLen   = 16
	pcapFile = ""
	heapFile = ""

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
		if i+keyLen > size {
			break
		}
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

func readHeap() {
	heap, err = ioutil.ReadFile(heapFile)
	if err != nil {
		panic(err)
	}
	//fmt.Println(hex.Dump(heap))
}

func IsAsciiPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func cleanupHeapString() {
	size := len(heap)
	i := 0
	for i < size {
		eightBytes := heap[i : i+8]
		stringTest := string(eightBytes[:])
		//fmt.Println(stringTest)
		//fmt.Println(hex.EncodeToString(eightBytes))
		//fmt.Println(IsAsciiPrintable(stringTest))

		if !IsAsciiPrintable(stringTest) {
			cleanHeap = append(cleanHeap, eightBytes...)
		}
		i += 8
	}
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

func readPcap() {
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

	fmt.Println("REQUEST SERVICE PACKET")
	fmt.Println(hex.Dump(serviceRequestPacket))
}

func isServer2Client(src net.IP) bool {
	return src.Equal(serverIp)
}

func usage() {
	fmt.Printf("usage: %s [mode (ctr/cbc)] [pcap file] [heap dump file] [key length]\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 4 {
		usage()
	}

	mode = args[0]
	pcapFile = args[1]
	heapFile = args[2]
	keyLen, err = strconv.Atoi(args[3])
	if err != nil {
		usage()
	}

	start := time.Now()
	readPcap()
	readHeap()
	fmt.Printf("Size before cleanup : %d\n", len(heap))
	cleanupHeap()
	heap = []byte{}
	heap = append(heap, cleanHeap...)
	cleanHeap = []byte{}
	cleanupHeapString()
	//cleanupHeapHamming()
	cleanHeapSize := len(cleanHeap)
	fmt.Printf("Size after cleanup : %d\n", cleanHeapSize)

	//let's brute force
	pbar := pb.StartNew(cleanHeapSize)
	i := 0

	gRoutineCount := 1

	for i < cleanHeapSize {

		var wg sync.WaitGroup

		//8-bytes aligned
		increment := gRoutineCount * 8

		pbar.Add(increment)

		x := 0
		for x < gRoutineCount {
			wg.Add(1)
			from := i + (16 * x)     //IV 16 bytes
			to := i + (16 * (x + 1)) //IV 16 bytes
			potentialIV := cleanHeap[from:to]
			//go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, to)

			// we have to start from offset 0 again, since at some version of openssh, actually location of
			// the key is earlier than ke IV. And on some version the key actually after the IV
			go bruteforceKey(&wg, potentialIV, serviceRequestPacket, cleanHeapSize, 0)
			x++
		}

		wg.Wait()

		//potentialIV := cleanHeap[i : i+16]
		//bruteforceKey(potentialIV, serviceRequestPacket, cleanHeapSize)

		if found {
			break
		}

		i += increment
	}
	elapsed := time.Since(start).Seconds()
	pbar.Finish()

	fmt.Printf("IV : %s\n", hex.EncodeToString(iv))
	fmt.Printf("KEY : %s\n", hex.EncodeToString(key))
	log.Printf("It took : %fs\n", elapsed)
}
