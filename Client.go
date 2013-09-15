package main

import ( 
  "net"     // provides the Listener and Conn types that hide many of the details of setting up socket connections
//  "bufio"   // provides buffered read methods, simplifying common tasks like reading lines from a socket
  "strconv" // function Itoa() that converts an integer to a string
  "fmt"     // for printing strings to the console
  "bytes"   // Compare bytes
  "crypto/cipher"
  "crypto/rand"
  "encoding/hex"
  "crypto/aes"
  "io"
)
// port that the server is going to listen
const S_PORT = 9000 
const S_ADDR = "10.110.0.144:"
const KEY = "0000000000000001"

func main() {

  fmt.Printf("Initializing Client...\n")
  server, err := net.Dial("tcp", S_ADDR + strconv.Itoa(S_PORT))
  if err != nil {
    fmt.Printf("Connection Refused: ")
	  panic(err)// handle error
  }  
   var msg = make([]byte, 512)
   server.Read(msg)
   n := bytes.Index(msg, []byte{0})
   s := string(msg[:n])
   fmt.Printf(s+"\n")
  
  fmt.Printf("Use $unsec for secure connections or $sec for unsecure:\n")
  Switch(server)
  
}

func Switch(server net.Conn){
  var message string
  continue_ch := make(chan int, 1)
  for{
    fmt.Scan(&message)
    if(message == "$unsec"){
      fmt.Printf("Unsecure connection with:\n")
      go HandleUnsec(server, continue_ch)
    } else if(message == "$sec"){
      fmt.Printf("Secure connection!\n")
      go HandleSec(server,continue_ch)
    }
     <- continue_ch 
  }

}

func HandleUnsec(server net.Conn, continue_ch chan int){
    server.Write([]byte("unsec\n"))

    var msg = make([]byte, 512)
	  server.Read(msg)
   
    n := bytes.Index(msg, []byte{0})
    s := string(msg[:n])
    fmt.Printf(s+"\n\n")

    unsec_server, err := net.Dial("tcp", s)
    if err != nil {
      fmt.Printf("Connection Refused: ")
	    panic(err)// handle error
    } 
 
    fmt.Printf("Now you can send your unsecure messages:\n")
    fmt.Printf("Use $end to finish the unsecure connection.\n")
    var message string

    for{
        fmt.Scanf("%s", &message)
        fmt.Printf("Lido: " + message +"\n")
        if(message == "$end"){
           break 
        }
        //unsec_server.Write([]byte(message))
        fmt.Fprintf(unsec_server, message+"\n")
        unsec_server.Read(msg)
        fmt.Printf("ECHO: ",msg,"\n");        
        n = bytes.Index(msg, []byte{0})
        s = string(msg[:n])
    }
    continue_ch <- 1
}

func HandleSec(server net.Conn, continue_ch chan int){
    server.Write([]byte("sec\n"))

    var msg = make([]byte, 512)
	  server.Read(msg)
    n := bytes.Index(msg, []byte{0})
    s := string(msg[:n])
    fmt.Printf(s+"\n\n")

    sec_server, err := net.Dial("tcp", s)
    if err != nil {
      fmt.Printf("Connection Refused: ")
	    panic(err)// handle error
    } 
 
    fmt.Printf("Now you can send your secure messages:\n")
    fmt.Printf("Use $end to finish the secure connection.\n")
    var message string

    for{
        fmt.Scanf("%s", &message)
        fmt.Printf("Lido: " + message +"\n")
       
        if(message == "$end"){
           break 
        } 
        msgEncrypted := Encrypter(message,KEY);
        //unsec_server.Write([]byte(message))
        fmt.Fprintf(sec_server, msgEncrypted+"\n")
        sec_server.Read(msg)
        
        n = bytes.Index(msg, []byte{0})
        s = string(msg[:n])
        msgDecrypted := Decrypter(s,KEY);
        fmt.Printf("ECHO: %s",msgDecrypted);        
        
        
    }
    continue_ch <- 1
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

	//fmt.Printf("%s\n", ciphertext)
	return ciphertext
}
