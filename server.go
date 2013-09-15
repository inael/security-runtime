// Simple GO server
package main

import (
  "net"     // provides the Listener and Conn types that hide many of the details of setting up socket connections
  "bufio"   // provides buffered read methods, simplifying common tasks like reading lines from a socket
  "strconv" // function Itoa() that converts an integer to a string
  "fmt"     // for printing strings to the console
  "bytes"   // Compare bytes
  "crypto/cipher"
	"crypto/rand"
//	"encoding/gob"
	"encoding/hex"
"crypto/aes"
"io"
)

const PORT = 9000 // port that the server is going to listen
const IP = "10.110.0.144:"
const KEY = "0000000000000001"

func main() {

  // we start by declaring and initializing a new listener for the server
  server, err := net.Listen("tcp", IP + strconv.Itoa(PORT))
  if server == nil {
    // exits the application
    panic(err)
  }

  conns := clientConns(server) // this is the channel we’ll use for getting new client connections.
  // infinite loop
  // each time we start a goroutine, with the value receive operation on our client connections channel.
  // the unary operator <- blocks until a value is available on the channel (a new client having connected)
  for { 
    go handleConn(<-conns)
  }
}

func clientConns(listener net.Listener) chan net.Conn {

   // channel that corresponds to the type that we’ll be got from calling Accept() on listener connection object
   ch := make(chan net.Conn)

   // anonymous goroutine which runs in an infinite loop, constantly accepting new connections  
   go func(){

    for{
      // blocks as long as there are no new clients to deal with 
      client, err := listener.Accept()
      if client == nil {
        fmt.Printf("couldn't accept: %s\n", err)
        continue
      }
      fmt.Printf("New connection with: %v established\n", client.RemoteAddr())
      // sends hello!
         byteMessage := []byte("Hello! Connection established with: " + listener.Addr().String() + ".\n")
         client.Write(byteMessage) 
      // send the client, of type net.Conn to the channel 
         ch <- client
    }

   }()
   return ch
}


// controls the main connection with client
func handleConn(client net.Conn) {

  // used to manage the connection
    unsec := []byte("unsec")
    sec   := []byte("sec")
    unsec_ch := make(chan int, 1)
	exit_unsec_ch := make(chan int,1)
    sec_ch :=   make(chan int,1)
	exit_sec_ch := make(chan int,1)

  // buffers the client req
  b := bufio.NewReader(client)

  for {
    line, err := b.ReadBytes('\n')
    if err != nil { // EOF, or worse
	fmt.Print("Error: Client Down!")	
      break
    }

    if(bytes.HasPrefix(line, unsec) == true){
      go HandleUnsec(client, exit_unsec_ch, sec_ch, exit_sec_ch)
	  fmt.Print("Unsec connection with ", client.RemoteAddr(), "\n")
	  unsec_ch <- 1		
    } else if(bytes.HasPrefix(line, sec) == true){
      fmt.Print("Sec connection with ", client.RemoteAddr(), "\n")
      go HandleSec(client, exit_sec_ch, unsec_ch, exit_unsec_ch)
      sec_ch <- 1 
    }
  }
}

func HandleUnsec (client net.Conn, exit_unsec_ch chan int, sec_ch chan int, exit_sec_ch chan int ) {
  select{
	  case <- sec_ch:
	    exit_sec_ch <- 1
	  default: 
  }
  
  // leave to the SO the responsability to choose an avaliable port
  unsec_server, err := net.Listen("tcp", IP+"0")
  if unsec_server == nil {
    // exits the application
    panic(err)
  }

  // announces to client the address 
  unsec_addr := []byte( unsec_server.Addr().String())
  client.Write(unsec_addr)

  //Waits for client to connect
    unsec_client, err := unsec_server.Accept()
    if unsec_client == nil {
        fmt.Printf("couldn't accept: %s\n", err)
        panic(err)
    }
     // buffers the client req
    // b := bufio.NewReader(unsec_client)  
     interrupt := false
    var cmd string  

  for {
    select {
      case <- exit_unsec_ch:
        interrupt = true
		    unsec_client.Write([]byte("Connection Closed!\n"))
        break
      default:
        fmt.Fscan(unsec_client, &cmd)  
       // line, err := b.ReadBytes('\n')
        //unsec_client.Read(line)
        if err != nil { // EOF, or worse
          break
        }
        fmt.Print("\nUnsec Message Received From: ", client.RemoteAddr(), "\n")
        //unsec_client.Write(line)
      //  n := bytes.Index(line, []byte{0})
    	//	s := string(line[:n])
        fmt.Fprintf(unsec_client, cmd)
        fmt.Printf(cmd)
    }
    if (interrupt == true){
      break
    }
  }
  unsec_server.Close()
}

func HandleSec (client net.Conn, exit_sec_ch chan int, unsec_ch chan int, exit_unsec_ch chan int ){ 
	select{
		case <- unsec_ch:
		 exit_unsec_ch <- 1
	 	default:
	}
 // leave to the SO the responsability to choose an avaliable port
  sec_server, err := net.Listen("tcp", IP+"0")
  if sec_server == nil {
	fmt.Printf("Seg erro")
    // exits the application
    panic(err)
  }

  // announces to client the address 
  sec_addr := []byte( sec_server.Addr().String())
  client.Write(sec_addr)

  //Waits for client to connect
    sec_client, err := sec_server.Accept()
    if sec_client == nil {
        fmt.Printf("couldn't accept: %s\n", err)
        panic(err)
    }
	
	 // buffers the client req
    // b := bufio.NewReader(sec_client)
	//Used to break the loop
 interrupt := false
 var cmd string  
  for {
    select {
      case <- exit_sec_ch:
        interrupt = true
		    sec_client.Write([]byte("Connection Closed!\n"))
        break
      default:
        fmt.Fscan(sec_client, &cmd)  
        if err != nil { // EOF, or worse
          break
        }		
		    fmt.Print("Sec Message Received From: ", client.RemoteAddr(),"\n")
	    
		    //mt.Printf("MSG criptografada em STRING ",cmd,"\n");		
		    msgPlane:= Decrypter(cmd, KEY)
		    fmt.Printf("MSG descriptografa %s \n",msgPlane) 	
        fmt.Fprintf(sec_client, cmd)    

    }
    if (interrupt == true){
      break
    }
  }
  sec_server.Close()
}


func Encrypter(plainText string, key string) string {
	keyByte := []byte(key)
	plaintext := []byte(plainText)
        if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	//Reader is a global, shared instance of a cryptographically strong pseudo-random generator
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	//NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode
	mode := cipher.NewCBCEncrypter(block, iv)
	//CryptBlocks encrypts or decrypts a number of blocks.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	//fmt.Printf("%x\n", ciphertext)

	return hex.EncodeToString(ciphertext) 
}

func Decrypter(cipherText string, key string) []byte {
	keyByte := []byte(key)
	ciphertext, _ := hex.DecodeString(cipherText)

	block, err := aes.NewCipher(keyByte)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

//	fmt.Printf("%s\n", ciphertext)
	return ciphertext
}

