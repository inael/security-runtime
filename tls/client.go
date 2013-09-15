package main
 
import (
   // "crypto/tls"
	"crypto/tls"
   // "crypto/x509"
    "fmt"
    "io"
    "log"
	"net"
)
//O Listen nao pode ter um config nil, mas o Dial pode
//1-Adicionar uma nova propriedade em tls.Config do tipo "type Config struct " in common.go para desligar o tls
//2- 
//Plano e adicionar uma nova funcao "func (c *Conn) Write(b []byte) (int, error)"
//que verifica se nas configuracoes esta setado como nao seguro, para escrever texto 
//plano e encriptado.
//O mesmo para a funcao "func (c *Conn) Read(b []byte) (n int, err error)"
//5-Pensar em uma forma de fechar uma conexao quando houver troca de sec para unsec e vice versa

func main() {
 
	//A Conn represents a secured connection. It implements the net.Conn interface.
    enableSec:= false;
    conn := DialSec("tcp", "127.0.0.1:8084", enableSec)
    
    log.Printf("client: connected to host: %s \n",  conn.connUnsec.RemoteAddr())
    
    var message string
    for{
	    fmt.Scan(&message)
		//Write writes data to the connection, call conn.Write([]byte(s))
	    n, err := io.WriteString(conn.connUnsec, message)
	    if err != nil {
		log.Fatalf("client: write: %s", err)
	    }
	    log.Printf("client: wrote %q (%d bytes)", message, n)
    }
    /*
    reply := make([]byte, 256)//create a buffer
	//Read reads data from the connection.
    n, err = conn.connUnsec.Read(reply)
    log.Printf("client: read %q (%d bytes)", string(reply[:n]), n) 
    */
    log.Print("client: exiting") 
}



 
type Conn struct {
	connUnsec net.Conn //connection unsecutiry
	connSec   *tls.Conn//connection security
	connConfig *tls.Conn//connection to configurations
	config ConfigSec//flat to enable security
}
type ConfigSec struct{
	enableSec bool;
}


func DialSec(network, addr string, enableSec bool) Conn {
	configSec:= ConfigSec{enableSec:enableSec}
	conn := Conn{config:configSec};
	hostToConnect :=HandShake(conn, network, addr, enableSec);	
	var err error;
	if(enableSec){
		log.Println("client: Setting Security Config");
		cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
		if err != nil {
			log.Fatalf("server: loadkeys: %s", err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		//A Conn represents a secured connection. It implements the net.Conn interface.
		conn.connSec, err = tls.Dial(network, hostToConnect, &config)
		if err != nil {
			log.Fatalf("client: dial: %s", err)
		}
		defer conn.connSec.Close()
		return conn;
		
	}else{
		log.Println("client: Starting Unsecuri Connection at ",hostToConnect);
		connUnsec,errUnsec:= net.Dial(network, hostToConnect);
		if errUnsec != nil  {
			log.Fatalf("client: dial: %s", err)
		}
		log.Println("client: Unsec Connection established ");
		c :=  Conn{config:configSec,connUnsec:connUnsec};
		return c;
	}
	
}
func HandShake(conn Conn, network, addr string, enableSec bool)(string){
	log.Println("client: Starting HandShake ConfigSec");
	cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	//A Conn represents a secured connection. It implements the net.Conn interface.
	conn.connConfig, err = tls.Dial(network, addr, &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	log.Println("client: HandShake Success!");
	
	defer conn.connConfig.Close()
	message :=""
	if(enableSec){
		
		message ="$sec"
	}else{
		message="$unsec"
	}
	log.Println("client: Requesting Connection ", message);
	//Write writes data to the connection, call conn.Write([]byte(s))
	n, err := io.WriteString(conn.connConfig, message)
	if err != nil {
		log.Fatalf("client: write: %s", err)
        }
        reply := make([]byte, 256)//create a buffer
	//Read reads data from the connection.
	n, err = conn.connConfig.Read(reply)
	hostToConnect:=string(reply[:n]);
	log.Printf("client: Server send the following host to connect: %s\n", hostToConnect)
	return hostToConnect;
}