/*
 * Copyright (C) 2022 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

var (
	PORT = flag.String("connect_port", "9990", "TCP port to connect to for packet stream")
	HOST = flag.String("connect_host", "localhost", "Packet Capture Agent IP")
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	fmt.Println("Starting Packet Capture Client.")
	fmt.Println("This creates a file capture.pcap and writes packets to it.")
	fmt.Println("To view captured packets 'tcpdump -r capture.pcap'.")
	tcpServer, err := net.ResolveTCPAddr("tcp", *HOST+":"+*PORT)

	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpServer)
	if err != nil {
		println("Dial failed:", err.Error())
		os.Exit(1)
	}
	f, err := os.Create("capture.pcap")
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()
	for {
		received := make([]byte, 65535)
		n, err := conn.Read(received)
		if err != nil {
			println("Read data failed:", err.Error())
			os.Exit(1)
		}
		_, err = f.Write(received[:n])
		check(err)
		dt := time.Now()
		fmt.Println(dt.Format("01-02-2006 15:04:05.000000"), ": Received Packet of length ", n)
	}
	conn.Close()
}
