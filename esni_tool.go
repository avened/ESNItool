// Small console utility for extracting from DNS and parsing 
// ESNI records (TXT, draft-2).
//
// Alexander Venedioukhin
// https://dxdt.ru/
//

package main

import (
	"fmt"
	"os"
	"net"
	"time"
	"math/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/miekg/dns"
)

type KeyShare struct {
		Group uint16
		Key []byte
}

type ESNIKeys struct {
           Version uint16;
           Checksum [4]byte;
           Keys []KeyShare
           Ciphers []uint16
           PaddedLength uint16;
           NotBefore uint64;
           NotAfter uint64;
           Extensions []byte
}

func (r *ESNIKeys) String() string{

	data := fmt.Sprintf("Version: %04X; Groups: ", r.Version)
	
	ff := true
	for _, v := range r.Keys {
		if ff {
			data = data + fmt.Sprintf("%04X", v.Group)
			ff = false
		}else{
			data = data + fmt.Sprintf(",%04X", v.Group)
		}
	}
	
	data = data + fmt.Sprintf("; Ciphers: ")
	
	ff = true
	for _, v := range r.Ciphers {
		if ff {
			data = data + fmt.Sprintf("%04X", v)
			ff = false
		}else{
			data = data + fmt.Sprintf(",%04X", v)
		}
	}
	
	data = data + fmt.Sprintf("; Validity: %s TO %s", time.Unix(int64(r.NotBefore), 0).UTC(), time.Unix(int64(r.NotAfter), 0).UTC())
	
	return data
	
}

func (r *ESNIKeys) StringFields() string{

	data := ""
	
	for _, v := range r.Keys {
		data = data + fmt.Sprintf("\tDH:\t\t0x%04X/0x%0X\n", v.Group, v.Key)
	}

	for _, v := range r.Ciphers {
			data = data + fmt.Sprintf("\tCipher:\t\t0x%04X\n", v)
	}
	
	data = data + fmt.Sprintf("\tNot-Before:\t%s\n\tNot-After:\t%s\n\n", time.Unix(int64(r.NotBefore), 0).UTC(), time.Unix(int64(r.NotAfter), 0).UTC())
	
	return data
	
}


func ProcessESNI(r string) (res *ESNIKeys, e string) {
var CheckSum [4]byte
var cOffset int

defer func() {
	if err := recover(); err != nil {
		e = "ESNI parser panic!"
		res = nil
		return
	}
}()

	res = new(ESNIKeys)
	res.Version = 0xFF01

	data, err := base64.StdEncoding.DecodeString(r)
	if err != nil {
		//fmt.Println("Base64 error:", err)
		return nil, "Bad decode"
	}
	
	if len(data) < 32 { 
		return nil, "Invalid ESNI format (too short)"
	}
	
	bytesLeft := len(data)
	if data[0] != 0xFF && data[1] != 0x01 {
		return nil, "Bad ESNI version value"
	}

	copy(CheckSum[:],data[2:6])
	
	for i := 2; i < 6; i++ {
		data[i] = 0
	}
	sum := sha256.Sum256(data)
	for i := 0; i < 4; i++ {
		if CheckSum[i] != sum[i] {
			return nil, "Checksum failure!"
		}
	}
	
	kLen := int(data[6]) << 8 + int(data[7])
	cOffset = 8
	bytesLeft = bytesLeft - 8
	
	if kLen > bytesLeft - 20 {
		return nil, "Bad format (key share length)"
	}
	
	if kLen <= 4 {
		return nil, "Bad format (invalid key share length)"
	}
	
	k_share_len := kLen
	for {
		
		if bytesLeft < 4 + 20 {
			return nil, "Bad format (key share data block)"
		}
		group_name := uint16(data[cOffset]) << 8 + uint16(data[cOffset+1])
		key_r_len := uint16(data[cOffset+2]) << 8 + uint16(data[cOffset+3])
		bytesLeft = bytesLeft - 4
		if bytesLeft < int(key_r_len) + 20 {
			return nil, "Bad format (key share representation)"
		}
		cOffset = cOffset + 4
		l := new(KeyShare)
		l.Group = group_name
		(*l).Key = append((*l).Key, data[cOffset:cOffset+int(key_r_len)]...)
		(*res).Keys = append((*res).Keys, *l)
		
		cOffset = cOffset + int(key_r_len)
		bytesLeft = bytesLeft - int(key_r_len)
		
		k_share_len = k_share_len - int(key_r_len) - 4
		if k_share_len < 0 {
			return nil, "Bad format (key lenghts mismatch)"
		}
		
		if k_share_len == 0 {
			break
		}
		
	}
	
	cipLen := int(data[cOffset]) << 8 + int(data[cOffset + 1])
	bytesLeft = bytesLeft - 2
	cOffset = cOffset + 2
	
	if cipLen > bytesLeft - 20 {
		return nil, "Bad format (ciphers field length)"
	}
	
	ciphers_data_len := cipLen
	
	for {
	
		if bytesLeft < 2 + 18 {
			return nil, "Bad format (ciphers list length)"
		}
		
		cipher := uint16(data[cOffset]) << 8 + uint16(data[cOffset + 1])
		
		(*res).Ciphers = append((*res).Ciphers, cipher)
		
		cOffset = cOffset + 2
		bytesLeft = bytesLeft - 2
		ciphers_data_len = ciphers_data_len - 2
		if ciphers_data_len < 0 {
			return nil, "Bad format (ciphers len mismatch)"
		}
		
		if ciphers_data_len == 0 {
			break
		}
	}
	
	if (bytesLeft < 18) || (cOffset >= len(data)){
		return nil, "Bad format (invalid length)"
	}
	
	res.PaddedLength = uint16(data[cOffset]) << 8 + uint16(data[cOffset + 1])
	cOffset = cOffset + 2
	bytesLeft = bytesLeft - 2
	
	res.NotBefore = uint64(data[cOffset]) << (7*8) + uint64(data[cOffset + 1]) << (6*8) +
					uint64(data[cOffset+2]) << (5*8) + uint64(data[cOffset + 3]) << (4*8) +
					uint64(data[cOffset+4]) << (3*8) + uint64(data[cOffset + 5]) << (2*8) +
					uint64(data[cOffset+6]) << (1*8) + uint64(data[cOffset + 7])
	
	bytesLeft = bytesLeft - 8
	cOffset = cOffset + 8
	res.NotAfter = uint64(data[cOffset]) << (7*8) + uint64(data[cOffset + 1]) << (6*8) +
					uint64(data[cOffset+2]) << (5*8) + uint64(data[cOffset + 3]) << (4*8) +
					uint64(data[cOffset+4]) << (3*8) + uint64(data[cOffset + 5]) << (2*8) +
					uint64(data[cOffset+6]) << (1*8) + uint64(data[cOffset + 7])
	
	bytesLeft = bytesLeft - 8
	cOffset = cOffset + 8
	
	if cOffset > len(data) - 2 {
		return nil, "Bad format (extensions field missing)"
	}
	
	ext_len := int(data[cOffset]) << 8 + int(data[cOffset + 1])
	bytesLeft = bytesLeft - 2
	cOffset = cOffset + 2
	
	if bytesLeft < ext_len {
		return nil, "Bad format (bad extensions length)"
	}
	
	copy((*res).Extensions, data[cOffset:cOffset + ext_len])
	return res, ""
}

func main() {

var label_chars string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-"
var name_srv []string
var msg string

	if len(os.Args) <= 1 {
		fmt.Printf("Not enough parameters!\nUsage: %s domain.tld\n\n", os.Args[0])
		return
	}else{
		fmt.Printf("\nESNI tool\nv.0.1.beta\nResolves ESNI TXT records, prints parsed result.\n(Resolvers are from /etc/resolv.conf file.)\n\n")
	}

	args := os.Args[1:]
	if len(args[0]) < 1{
		fmt.Printf("INFO: Empty input, using example.com instead.\n")
		args[0] = "example.com."
	}else{
		double_dot := false
		for i, m := range args[0]{
			if m == '.'{
				if double_dot{
					fmt.Printf("Bad name %s - empty label at position %d!\n", args[0], (i + 1))
					return
				}else{
				double_dot = true
				}
			}else{
				if double_dot {
					double_dot = false
				}
			}
			not_found := true
			LOOP:
			for _, n := range label_chars{
				if m == n {
					not_found = false
					break LOOP
				}
			}
			if not_found {
				fmt.Printf("Bad name %s (invalid char at position %d)!\n", args[0], (i + 1))
				return
			}
		}
		if args[0][len(args[0])-1] != '.' {
			args[0] = args[0] + "."
		}
	}
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		panic(err)
	}
	for _, server := range conf.Servers{
		nsrv := server
		if nsrv[0] == '[' && nsrv[len(nsrv)-1] == ']' {
			nsrv = nsrv[1 : len(nsrv)-1]
		}
		if i := net.ParseIP(nsrv); i != nil {
			nsrv = net.JoinHostPort(nsrv, "53")
		} else {
			nsrv = dns.Fqdn(nsrv) + ":" + "53"
		}
		fmt.Printf("Resolver (system): %s\n", nsrv)
		name_srv = append(name_srv, nsrv)
	}
	c := new(dns.Client)
	m := new(dns.Msg)
	if args[0][0] == '.'{
		msg = "_esni" + args[0]
	}else{
		msg = "_esni." + args[0]
	}
	tell_number := rand.Intn(len(name_srv))
	fmt.Printf("\n\tInput name: %s\n\tConstructed name: %s\n\tUsing resolver %s\n\nPerforming DNS lookup...", args[0], msg, name_srv[tell_number])
	
	m.SetQuestion(msg, dns.TypeTXT)
	in, _, err := c.Exchange(m, name_srv[0])
	empty := true
	if err == nil && in != nil {
		fmt.Printf("OK\n")
		if len(in.Answer) > 0 {
			for _, val := range in.Answer{
				if t, ok := val.(*dns.TXT); ok {
					empty = false
					to_parse := ""
					fmt.Printf("\nSource value:\n")
					for _, v := range t.Txt {
						fmt.Printf("\t%s", v)
						to_parse = to_parse + v
					}
					ESNI_parsed, status := ProcessESNI(to_parse)
					if status != "" {
						fmt.Printf("\n\nNo ESNI (invalid data; status: %s)\n\n", status)
					}else{								
						fmt.Printf("\n\nESNI for %s:\n%s\n\n", args[0], ESNI_parsed.StringFields())
							}
				}
			}
		}
	}else{
			fmt.Printf("Failed (%s)!\n", err)
			empty = false
	}
	if empty {
		fmt.Printf("Empty answer (no TXT)!\n\n")
	}
}
