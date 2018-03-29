package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

type TLS struct {
	Country    []string "GB"
	Org        []string "Staaldraad"
	CommonName string   "*.domain.com"
}

type Config struct {
	RemoteHost  string ""
	ListenAddr  string ""
	TLS        *TLS
	LocalCertFile   string ""
	LocalKeyFile    string ""
	LocalTls   bool
	RemoteTls  bool
}

var config Config
var ids = 0

func genCert() ([]byte, *rsa.PrivateKey) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:      config.TLS.Country,
			Organization: config.TLS.Org,
			CommonName:   config.TLS.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		fmt.Println("create ca failed", err)
	}
	return ca_b, priv
}

func handleServerMessage(connR, connC net.Conn, id int) {
	for {
		data := make([]byte, 2048)
		n, err := connR.Read(data)
		if n > 0 {
			connC.Write(data[:n])
			fmt.Printf("From Server [%d]:\n%s\n", id, hex.Dump(data[:n]))
			//fmt.Printf("From Server:\n%s\n",hex.EncodeToString(data[:n]))
		}
		if err != nil && err != io.EOF {
			fmt.Println(err)
			break
		}
	}
}

func handleConnection(conn net.Conn) {
	var err error
	var connR net.Conn

	if config.RemoteTls == true {
		conf := tls.Config{InsecureSkipVerify: true}
		connR, err = tls.Dial("tcp", config.RemoteHost, &conf)
	} else {
		connR, err = net.Dial("tcp", config.RemoteHost)
	}

	if err != nil {
		return
	}

	fmt.Printf("[*][%d] Connected to server: %s\n", ids, connR.RemoteAddr())
	id := ids
	ids++
	go handleServerMessage(connR, conn, id)
	for {
		data := make([]byte, 2048)
		n, err := conn.Read(data)
		if n > 0 {
			fmt.Printf("From Client [%d]:\n%s\n", id, hex.Dump(data[:n]))
			//fmt.Printf("From Client:\n%s\n",hex.EncodeToString(data[:n]))
			connR.Write(data[:n])
			_ = hex.Dump(data[:n])
		}
		if err != nil && err == io.EOF {
			fmt.Println(err)
			break
		}
	}
	connR.Close()
	conn.Close()
}

func startListener() {
	var err error
	var conn net.Listener
	var cert tls.Certificate

	if config.LocalTls == true {
		fmt.Printf("starting TLS listener\n")
		if config.LocalCertFile != "" {
			cert, err = tls.LoadX509KeyPair(config.LocalCertFile, config.LocalKeyFile)
			if err != nil {
				panic("failed to parse the provided certificates: " + err.Error())
			}
		} else {
			ca_b, priv := genCert()
			cert = tls.Certificate{
				Certificate: [][]byte{ca_b},
				PrivateKey:  priv,
			}
		}

		conf := tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		conf.Rand = rand.Reader

		conn, err = tls.Listen("tcp", config.ListenAddr, &conf)
	} else {
		fmt.Printf("starting raw TCP listener\n")
		conn, err = net.Listen("tcp", config.ListenAddr)
	}

	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	fmt.Println("[*] Listening...")

	for {
		cl, err := conn.Accept()
		if err != nil {
			fmt.Printf("server: accept: %s", err)
			break
		}
		fmt.Printf("[*] Accepted from: %s\n", cl.RemoteAddr())
		go handleConnection(cl)
	}
	conn.Close()
}

func setConfig(configFile string, listenAddr string, remoteHost string, localTls bool, remoteTls bool, localCertFile string, localKeyFile string) {
	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
		err = json.Unmarshal(data, &config)
		if err != nil {
			fmt.Println("[-] Not a valid config file: ", err)
			os.Exit(1)
		}
	} else {
		config = Config{TLS: &TLS{}}
	}

	config.ListenAddr = listenAddr
	config.RemoteHost = remoteHost
	config.LocalCertFile = localCertFile
	config.LocalKeyFile = localKeyFile
	config.LocalTls = localTls
	config.RemoteTls = remoteTls
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8080", "Local address to listen on")
	remoteHost := flag.String("remote", "", "Remote server to connect to example.com:80")
	configPtr := flag.String("config", "", "Use a config file (commandline params override config file)")
	localTls := flag.Bool("local-tls", false, "Enable TLS for local listener")
	remoteTls := flag.Bool("remote-tls", false, "Enable TLS for remote connection")
	localCertFile := flag.String("local-cert", "", "Use a specific certificate file for local listener (PEM)")
	localKeyFile := flag.String("local-key", "", "Use a specific key file for local listener (PEM)")

	flag.Parse()

	setConfig(*configPtr, *listenAddr, *remoteHost, *localTls, *remoteTls, *localCertFile, *localKeyFile)

	if config.RemoteHost == "" {
		fmt.Println("[x] Remote host required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	startListener()
}
