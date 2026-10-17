package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"

	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
)

func masqueradeVector(target string) error {
	var request struct {
		Packet string
		Source bool
	}
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 150000)).Decode(&request); err != nil {
		return err
	}
	bytes, err := hex.DecodeString(request.Packet)
	if err != nil {
		return err
	}
	address, err := netip.ParseAddr(target)
	if err != nil {
		return err
	}
	var parsed packet.Parsed
	parsed.Decode(bytes)
	if request.Source {
		checksum.UpdateSrcAddr(&parsed, address)
	} else {
		checksum.UpdateDstAddr(&parsed, address)
	}
	return json.NewEncoder(os.Stdout).Encode(hex.EncodeToString(bytes))
}
