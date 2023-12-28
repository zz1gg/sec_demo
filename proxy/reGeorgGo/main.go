package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Constants
	S5VER            = 0x05
	S4VER            = 0x04
	READBUFSIZE      = 2048
	SOCKTIMEOUT      = 2 * time.Second
	BASICCHECKSTRING = "Georg says, 'All seems fine'"
)

// Session represents a session for handling SOCKS proxy connections.
type Session struct {
	clientConn    net.Conn
	httpClient    *http.Client
	cookie        string
	target        string
	targetPort    int
	connectString string
	data          []byte
	fowardflag    bool
}

// NewSession creates a new Session instance.
func NewSession(clientConn net.Conn, connectString string) *Session {
	session := &Session{
		clientConn:    clientConn,
		connectString: connectString,
		cookie:        "",
		// Initialize the `httpClient` field.
		httpClient: &http.Client{},
	}
	return session
}

func (s *Session) parseSocks4(buf []byte) bool {
	log.Println("Socks Version4 detected")
	cmd := buf[1]
	if cmd == 0x01 {
		//log.Println("Socks4's CMD: CONNECT")
		s.targetPort = int(binary.BigEndian.Uint16(buf[2:4]))
		s.target = net.IP(buf[4:8]).String()
		//log.Println("ip: port: ", s.target, s.targetPort)
		log.Printf("The destination address has been acquired.[%s:%d]...\n", s.target, s.targetPort)
		log.Println("Forward instruction....")
		//Establish a session and retrieve the cookie.
		cookie_ok := s.SetupRemoteSession()

		//log.Println("parseSocks4's cookie:", s.cookie)
		response := make([]byte, 8) //The total length of the Socks4 response message is 8 bytes.
		if cookie_ok == true {
			//Respond to the client with a successful connection establishment.
			response[0] = 0x00 // Version
			response[1] = 0x5A //The connection has been successfully established.
			//Configure the target IP and port.
			targetIP := net.ParseIP(s.target)
			copy(response[2:6], targetIP.To4())
			response[6] = byte(s.targetPort >> 8)   //high
			response[7] = byte(s.targetPort & 0xFF) // low
			// send response
			_, err := s.clientConn.Write(response)

			if err != nil {
				log.Fatalf("Response tunnel server Failed with: %v\n", err)
				log.Fatalln("Failed to write data to the Socks4 response.", err)
				return false
			}
			log.Println("Socks4 response sent successfully!")
			return true
		} else {
			response[0] = 0x00 // version
			response[1] = 0x5B //The connection has been refused or has failed.
			//Configure the target IP and port.
			targetIP := net.ParseIP(s.target)
			copy(response[2:6], targetIP.To4())
			response[6] = byte(s.targetPort >> 8)   // high
			response[7] = byte(s.targetPort & 0xFF) // low
			//Send the response.
			_, err := s.clientConn.Write(response)
			if err != nil {
				log.Fatalf("Response tunnel server Failed with: %v\n", err)
				return false
			}
		}

	} else {
		log.Fatalf("socks4 - command %d not implemented", cmd)
		return false
	}
	return false
}

func (s *Session) parseSocks5(buf []byte) bool {
	log.Println("SocksVersion5 detected")
	//Transmit to the client the supported authentication methods of the server (no authentication required).
	s.clientConn.Write([]byte{0x05, 0x00})
	//socks5 client -> socks5 server
	_, err := s.clientConn.Read(buf[:])
	if err != nil {
		log.Fatalln("Failed to read data from the buffer: ", err)
		return false
	}

	cmd := buf[1]
	atyp := buf[3]
	rsv := buf[2]
	if rsv == 0x02 {
		//log.Println("rsv:", rsv)
		log.Println("rsv is 0x02, this is a hack for proxychains", rsv)
	}
	//log.Println("rsv:", rsv)

	if atyp == 0x01 { // IPv4
		//Read the 4-byte IPv4 address and the 2-byte port number.
		s.target = net.IP(buf[4:8]).String()
		s.targetPort = int(binary.BigEndian.Uint16(buf[8:10]))
	} else if atyp == 0x03 { // Hostname
		targetLen := int(buf[4])
		s.target = string(buf[5 : 5+targetLen])
		s.targetPort = int(binary.BigEndian.Uint16(buf[5+targetLen : 7+targetLen]))
	} else if atyp == 0x04 { // IPv6
		//Retrieve the 16-byte IPv6 address and the 2-byte port number.
		s.target = net.IP(buf[4:20]).String()
		s.targetPort = int(binary.BigEndian.Uint16(buf[20:22]))
	}

	log.Printf("The destination address has been acquired:  [%s:%d]...\n", s.target, s.targetPort)

	switch cmd {
	case 0x02: // BIND
		//return errors.New("Socks5 - BIND not implemented")
		log.Println("Socks5 - BIND not implemented")

	case 0x03: // UDP
		//return errors.New("Socks5 - UDP not implemented")
		log.Println("Socks5 - UDP not implemented")

	case 0x01: // CONNECT
		//Obtain the IP address of the target server through hostname resolution.
		log.Println("Forward instruction....")
		serverIP := s.target
		if net.ParseIP(s.target) == nil {
			addr, err := net.ResolveIPAddr("ip", s.target)
			if err != nil {
				log.Println("oeps")
			}
			serverIP = addr.IP.String()
		}
		//log.Println("serverIP", serverIP)

		// Establish a remote session and acquire the cookie.
		cookie_ok := s.SetupRemoteSession()

		//log.Println("PareseSocks5 cookie:", s.cookie)

		if cookie_ok == true {
			// successful response to the client, including protocol version, success flag, reserved field, address type, target IP address, and port number.
			response := []byte{0x05, 0x00, 0x00, atyp}
			response = append(response, net.ParseIP(serverIP).To4()...)
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(s.targetPort))
			response = append(response, portBytes...)
			_, err := s.clientConn.Write(response)
			if err != nil {
				log.Println("Failed to write data to the Socks5 response.", err)
				return false
			}

			return true
		} else {
			// failed response to the client, including protocol version, success flag, reserved field, address type, target IP address, and port number.
			response := []byte{0x05, 0x05, 0x00, atyp}
			response = append(response, net.ParseIP(serverIP).To4()...)
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(s.targetPort))
			response = append(response, portBytes...)
			s.clientConn.Write(response)
			fmt.Errorf("[%s:%d] Remote failed", s.target, s.targetPort)
			return false
		}

	}
	//Throw an unimplemented protocol exception if the command is not 0x01.
	fmt.Errorf("Socks5 - Unknown CMD")
	return false
}

// SetupRemoteSession sets up a remote session by sending an HTTP request to the target server.
func (s *Session) SetupRemoteSession() bool {

	headers := http.Header{"X-CMD": []string{"CONNECT"}, "X-TARGET": []string{s.target}, "X-PORT": []string{(strconv.Itoa(s.targetPort))}}

	// Create an HTTP connection to the target server
	//httpconn := &http.Client{}
	url := fmt.Sprintf("%s?cmd=connect&target=%s&port=%d", s.connectString, s.target, s.targetPort)
	//log.Println("url", url)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Println("Failed to construct the HTTP request.", err)
		return false
	}
	req.Header = headers

	// Send the HTTP request
	resp, err := s.httpClient.Do(req)
	//log.Println("setupRemoteSession Response:", resp)
	log.Println("【SetupRemoteSession】Establish the remote connection...")
	if err != nil {
		log.Println("【SetupRemoteSession】Failed to establish the request... ", resp)
		return false
	}

	//defer resp.Body.Close()

	// Check the response for a successful connection and get the cookie
	if resp.StatusCode == http.StatusOK {
		status := resp.Header.Get("x-status")
		if status == "OK" {
			cookie := resp.Header.Get("Set-Cookie")
			s.cookie = cookie
			log.Println("The HTTP connection has been successfully established -> s.cookie:", s.cookie)
			log.Printf("【SetupRemoteSession】[%s:%d] HTTP Response Code : [200], with cookie [%s]\n", s.target, s.targetPort, s.cookie)
			return true
		} else {
			if errHeader := resp.Header.Get("X-ERROR"); errHeader != "" {
				fmt.Sprintf("[%s:%d] HTTP [%d]: RemoteError: %s", s.target, s.targetPort, resp.StatusCode, resp.Header.Get("X-ERROR"))
				return false
			}

		}
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("[%s:%d] HTTP [%d]: [%s]\n", s.target, s.targetPort, resp.StatusCode, resp.Header.Get("X-ERROR"))
		fmt.Printf("[%s:%d] RemoteError: %s\n", s.target, s.targetPort, string(body))
		return false

	}

	fmt.Errorf("Remote connection failed")
	return false
}

// CloseRemoteSession closes the remote session.
func (s *Session) CloseRemoteSession() {
	headers := map[string]string{
		"X-CMD":  "DISCONNECT",
		"Cookie": s.cookie,
	}
	url := fmt.Sprintf("%s?cmd=disconnect", s.connectString)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	// Send the HTTP request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

//Receive data from the HTTP tunnel and write it to the local socket.
func (s *Session) Reader(ch1 chan []byte, wg sync.WaitGroup) {

	for {
		if s.clientConn == nil {
			break
		}

		headers := http.Header{"X-CMD": []string{"READ"}, "Cookie": []string{s.cookie}, "Connection": []string{"Keep-Alive"}}
		url := fmt.Sprintf("%s?cmd=read", s.connectString)
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			log.Println("Failed to create HTTP request:", err)
			break
		}
		req.Header = headers

		//log.Println("Reader Request Header:", headers)
		response, err := s.httpClient.Do(req)
		if err != nil {
			log.Println("Failed to send read request:", err)
			break
		}
		defer response.Body.Close()
		//log.Println("Reader response:", response)

		//s.data = data
		if response.StatusCode == http.StatusOK {

			status := response.Header.Get("x-status")
			if status == "OK" {
				//log.Println("HTTP Status is OK!")
				log.Println("【Reader】HTTP Tunnel Status: OK")
				if response.Header.Get("set-cookie") != "" {

					s.cookie = response.Header.Get("set-cookie")
				}

				log.Println("【Reader】Read the result from socks...")
				s.data, _ = ioutil.ReadAll(response.Body)

				if len(s.data) > 0 {

					log.Printf("【Reader】[%s:%d] <<<< [%d]\n", s.target, s.targetPort, len(s.data))

					s.clientConn.Write(s.data) //send the data to client
					ch1 <- s.data
					break
					//stop Writer

				}
				if len(s.data) == 0 { //sleep & continue
					time.Sleep(time.Millisecond * 100)
					//call Writer
					s.fowardflag = true
					//ch1 <- 1
					ch1 <- s.data
					s.Writer(ch1)
					continue
				}
			} else {
				s.data = nil
				log.Printf("【Reader】[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down\n", s.target, s.targetPort, response.StatusCode, status, response.Header.Get("x-error"))
				break
			}

		} else { //
			log.Printf("【Reader】[%s:%d] HTTP [%d]: Shutting down\n", s.target, s.targetPort, response.StatusCode)
		}

	}

	/*
		if s.clientConn != nil {
			s.clientConn.Close()
			log.Printf("【Reader】[%s:%d]Localsocket already closed", s.target, s.targetPort)
		}

	*/

	wg.Done()
	s.fowardflag = false
	s.CloseRemoteSession()
	log.Printf("【Reader】[%s:%d] Closing local socket\n", s.target, s.targetPort)

}

// Writer reads data from socks and forwards it to the webserver.
func (s *Session) Writer(ch1 chan []byte) {

	switch s.fowardflag {

	case true:

		for {

			_, ok := <-ch1
			if !ok {
				fmt.Println("【Writer】Received a notification from the reader, close the forwarding.")
				break
			}
			data := make([]byte, READBUFSIZE)
			n, err := s.clientConn.Read(data)
			if err != nil {
				log.Println("【Writer】Writer read socks's data failed:", err)
				//break
			}

			data = data[:n]
			//log.Println("Writer Body:", string(data))

			body := bytes.NewReader(data)
			//log.Println("Writer s.data:", s.tempData)

			headers := http.Header{"X-CMD": []string{"FORWARD"}, "Cookie": []string{s.cookie}, "Content-Type": []string{"application/octet-stream"}, "Connection": []string{"Keep-Alive"}}
			url := fmt.Sprintf("%s?cmd=forward", s.connectString)
			req, err := http.NewRequest("POST", url, body)
			if err != nil {
				log.Println("Failed to create HTTP request:", err)
				break
			}
			//log.Println("Writer Request Header:", headers)
			req.Header = headers
			response, err := s.httpClient.Do(req)
			if err != nil {
				log.Println("Failed to send forward request:", err)
				break
			}
			defer response.Body.Close()
			//	log.Println("Writer response:", response)

			if response.StatusCode == http.StatusOK {
				status := response.Header.Get("x-status")

				if status == "OK" {
					if response.Header.Get("set-cookie") != "" {
						s.cookie = response.Header.Get("set-cookie")

						return
					}
				} else { //If HTTP response status is not ok, log the error message, close the connection, and exit the loop
					log.Printf("【Writer】[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down\n", s.target, s.targetPort, response.StatusCode, status, response.Header.Get("x-error"))
					break
				}
			} else { //If the HTTP response status code is not 200, log the error message, close the connection, and exit the loop.
				log.Printf("【Writer】[%s:%d] HTTP [%d]: Shutting down\n", s.target, s.targetPort, response.StatusCode)
				break
			}

			log.Printf("【Writer】[%s:%d] >>>> [%d]\n", s.target, s.targetPort, len(s.data))

		}

	case false:
		s.CloseRemoteSession() //Close remote Session
		log.Printf("【Writer】[%s:%d] Closing local socket\n", s.target, s.targetPort)

	}

}

// HandleSocks handles the SOCKS protocol, reads the client's request, and sets up the connection to the target server.
func (s *Session) HandleSocks() error {
	// Read the SOCKS protocol version
	var wg sync.WaitGroup

	buf := make([]byte, READBUFSIZE)
	_, err := s.clientConn.Read(buf)
	if err != nil {
		return err
	}
	//log.Println("Handle's buf:", buf)
	//log.Println("HandleSocks s.clientConn:", s.clientConn)
	ver := buf[0]
	ch := make(chan []byte, READBUFSIZE)
	defer close(ch)
	wg.Add(2)
	//Handle the request based on different protocol versions
	if ver == S4VER {
		//s.parseSocks4(buf)
		if s.parseSocks4(buf) == true {

			log.Println("Socks4 proxy has been established, cookie retrieval is complete, proceed with reading.")
			go s.Reader(ch, wg)
			wg.Wait()
			//s.Writer()
		}
	} else if ver == S5VER {
		if s.parseSocks5(buf) == true {

			log.Println("Socks5 proxy has been established, cookie retrieval is complete, proceed with reading.")
			go s.Reader(ch, wg)
			wg.Wait()

		}

	} else {
		return fmt.Errorf("Unsupported SOCKS version: 0x%X", ver)
	}

	return nil
}

//Check HTTP tunnel alive
func askGeorg(Tunnelurl string) bool {

	conn := http.Client{}
	resp, err := conn.Get(Tunnelurl)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	//log.Println("http body: ", body)
	if err != nil {
		log.Fatal(err)
	}

	if BASICCHECKSTRING == strings.TrimSpace(string(body)) {
		log.Println(BASICCHECKSTRING)
		return true
	}
	return false
}

func main() {

	//u := flag.String("host", "localhost", "Host name or IP address")
	var (
		tunnelurl string
		laddr     string
		lport     string
	)

	usage := `
Example:
./reGeorgGo -l 127.0.0.1 -p 1080 -u http://192.168.69.133:8000/tunnel.nosocket.php
    `

	flag.StringVar(&tunnelurl, "u", "", "The url containing the tunnel script")
	flag.StringVar(&laddr, "l", "127.0.0.1", "The default listening address")
	flag.StringVar(&lport, "p", "1080", "The default listening port")

	flag.Usage = func() {
		fmt.Printf("Usage: %s [OPTIONS]\n", os.Args[0])
		fmt.Println(`./reGeorgGo [-l addr] [-p port] [-u http tunnel url]`)
		fmt.Println(usage)
		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NFlag() == 0 && flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	log.Println("Checking if Georg is ready")

	if !askGeorg(tunnelurl) {
		log.Fatalln("Georg is not ready, please check Tunnel URL")
	}

	if (tunnelurl != "") || (tunnelurl != "" && laddr == "" && lport != "") {
		reGeorg(tunnelurl, laddr, lport)
	} else {
		flag.Usage()
	}
}

func reGeorg(tunnelurl, laddr, lport string) {

	//listenAddr := "127.0.0.1:1080"
	listenAddr := laddr + ":" + lport
	listener, err := net.Listen("tcp", listenAddr)

	if err != nil {
		fmt.Printf("Failed to listen on %s: %v\n", listenAddr, err)
		return
	}
	log.Printf("Listening on %s\n", listenAddr)

	for {

		clientConn, err := listener.Accept()
		clientConn.SetReadDeadline(time.Now().Add(SOCKTIMEOUT))
		if err != nil {
			fmt.Printf("Failed to accept client connection: %v\n", err)
			continue
		}
		go func() {
			defer clientConn.Close()
			// Create a new Session for each client connection
			session := NewSession(clientConn, tunnelurl)
			err := session.HandleSocks()
			if err != nil {
				fmt.Printf("SOCKS handshake failed: %v\n", err)
			}
			//session.run()
		}()
	}
}
