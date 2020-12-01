#!/bin/bash

set -ev

go test github.com/nibeh/gopacket
go test github.com/nibeh/gopacket/layers
go test github.com/nibeh/gopacket/tcpassembly
go test github.com/nibeh/gopacket/reassembly
go test github.com/nibeh/gopacket/pcapgo 
go test github.com/nibeh/gopacket/pcap
