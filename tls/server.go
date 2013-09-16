package main
 
import (
    "crypto/rand"
    "crypto/tls"
    "log"
    "bytes" 
    "strconv"
    "net"
    "crypto/x509"
)
type ConfigSec struct{
	enableSec bool;
}
const IP = "127.0.0.1:"
const PORT =8084
func main() {
    cert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server.key")
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}}
    config.Rand = rand.Reader
    
    service := IP + strconv.Itoa(PORT)
    listener, err := tls.Listen("tcp", service, &config)
    if err != nil {
        log.Fatalf("server: listen: %s", err)
    }
    log.Print("server: listening config")
    for {
        connConfig, err := listener.Accept()
        if err != nil {
            log.Printf("server: accept: %s", err)
            break
        }
        defer connConfig.Close()
        log.Printf("server: accepted from %s", connConfig.RemoteAddr())
        tlscon, ok := connConfig.(*tls.Conn)
        if ok {
            state := tlscon.ConnectionState()
            for _, v := range state.PeerCertificates {
                log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
            }
        }
        go handleConnConfig(connConfig)
    }
}
 
func handleConnConfig(connConfig net.Conn) {
    defer connConfig.Close()
    for {
    	
    	buf := make([]byte, 512)
    	log.Print("server: conn: waiting")
        n, err := connConfig.Read(buf)
        if err != nil {
            if err != nil {
                log.Printf("server: conn: read: %s", err)
            }
            break
        }
	log.Printf("server: conn: echo %q\n", string(buf[:n]))
	insec:=[]byte("$insec")
	if(bytes.HasPrefix(buf, insec) == true){
	  log.Printf("server: Client wish start a Unsec Connection");
          insec_server, err := net.Listen("tcp", IP+"0")
          if insec_server == nil {
	    // exits the application
	    panic(err)
	  }
	  log.Printf("server: Unsecure Connection was open at %s",insec_server.Addr().String());
  	  // announces to client the address 
  	  insec_addr := []byte( insec_server.Addr().String())
  	  n, err = connConfig.Write(insec_addr)
          log.Printf("server: Sending  Ip:Port to Client Unsec Connect %s",insec_addr)
          if err != nil {
            log.Printf("server: write: %s", err)
            break
          }
          go handleUnsecConn(insec_server);
        }
    }
    log.Println("server: conn: closed")
}
func handleUnsecConn(insec_server net.Listener){
	connUnsec, err := insec_server.Accept()
	for{
		
		log.Printf("------------ %s -------------",insec_server.Addr().String());
		if err != nil {
		    log.Printf("server: accept: %s", err)
		    break
		}
		buf := make([]byte, 512)
		log.Print("server: conn: waiting")
		n, err := connUnsec.Read(buf)
		if err != nil {
		    if err != nil {
			log.Printf("server: conn: read: %s", err)
		    }
		    break
		}
		log.Printf("server: conn: echo %q\n", string(buf[:n]))
		n, err = connUnsec.Write(buf[:n])
		
		
	}

}