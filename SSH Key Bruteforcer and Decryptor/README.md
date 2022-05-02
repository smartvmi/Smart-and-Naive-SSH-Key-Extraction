# SSH Keys Bruteforce and Decryptor

For this current version, it supports only aes128-ctr, aes192-ctr and aes256-ctr (key length: 16, 24, 32 respectively).

## Requirements

To be able to run this codes, you need to have:
- Go
- libpcap

## Decrypt a single pcap file

```shell
go run ./single-decrypt/decrypt.go ctr <pcap file> <corresponding json file>
````

## Bruteforce a single pcap file -- Key A & C

```shell
go run ./naive-single-bruteforce/bruteforce.go ctr <pcap file> <corresponding heap dump file> <key length>
````

## Bruteforce multiple files inside a folder (naively) -- Key A & C

```shell
go run ./naive-all-bruteforce/bruteforce.go ctr <location (folder) of the pcap/heap dump file> <key length>
````

## Bruteforce a single pcap file using outfrom from the machine learning method -- Key A & C

```shell
go run ./from-ml-single-bruteforce/bruteforce.go ctr <pcap file> <slice/key file> <key length>
```

## Bruteforce multiple files inside a folder (using machine learning's output) -- Key A & C

```shell
go run ./from-ml-bruteforce-all-ac/bruteforce.go ctr <location (folder) of the pcap file> <key length>
```

## Bruteforce multiple files inside a folder (using machine learning's output) -- Key B & D

```shell
go run ./from-ml-bruteforce-all-bd/bruteforce.go ctr <location (folder) of the pcap file> <key length>
```