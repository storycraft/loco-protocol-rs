# loco-protocol - Loco protocol implementation

Open source Loco protocol implemention made with rust

## Specification
### Command
| name      | size              |
|-----------|-------------------|
| header    | (Header) 22 bytes |
| data      | header.data_size  |

#### Header
| name      | size     |
|-----------|----------|
| id        | 4 bytes  |
| status    | 2 bytes  |
| name      | 11 bytes |
| data_type | 1 bytes  |
| data_size | 4 bytes  |

### Secure data
| name           | size               |
|----------------|--------------------|
| header         | (Header) 20 bytes  |
| encrypted data | header.size - 16   |

#### Header
| name      | size     |
|-----------|----------|
| iv        | 16 bytes |
| size      | 4 bytes  |

#### Handshake
| name             | size       |
|------------------|------------|
| key size         | 4 bytes    |
| key_encrypt_type | 4 bytes    |
| encrypt_type     | 4 bytes    |
| key              | 256 bytes  |

Note: current implemention only supports RSA-AES


## Example
```rust
use std::{net::{TcpListener, TcpStream}, thread, io};
use openssl::rsa::Rsa;
use loco_protocol::{command::{Command, Error, Header, processor::CommandProcessor}, io::SecureClientStream, io::SecureServerStream, secure::CryptoStore};
    
fn main() {
    let key = Rsa::generate(2048).expect("Cannot generate rsa key pairs.");
    
    let socket = TcpListener::bind("127.0.0.1:5022").expect("Cannot bind tcp server");
    socket.set_nonblocking(true).expect("Cannot set socket to unblocked mode");
    
    let tcp = TcpStream::connect("127.0.0.1:5022").expect("Cannot connect tcp stream");
    tcp.set_nonblocking(true).expect("Cannot set client stream to unblocked mode");
    
    let mut client = CommandProcessor::new(
        SecureClientStream::new(
            CryptoStore::new().unwrap(),
            key.clone(),
            tcp
        )
    );
    
    let command = Command {
        header: Header {
            id: 0,
            status: 0,
            name: [72_u8, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0],
            data_type: 0,
            data_size: 5
        },
        
        data: "Hello".as_bytes().into(),
    };
    
    client.write_commmand(command.clone()).expect("Failed to send command");
    println!("CLIENT -> {:?}", command.clone());
    
    loop {
        match socket.accept() {
    
            Ok(connection) => {
                let key = key.clone();

                thread::spawn(move || {
                    let mut server = CommandProcessor::new(
                        SecureServerStream::new(
                            CryptoStore::new().unwrap(),
                            key,
                            connection.0
                        )
                    );
    
                    println!("Connected from {}", connection.1);
                    loop {
                        match server.read_commmand() {
    
                            Ok(readed) => {
                                if readed.is_some() {
                                    let received = readed.unwrap();
                                    println!("SERVER <- {:?}", received.clone());
    
                                    server.write_commmand(received.clone()).expect("Command failed to write");
                                    println!("SERVER -> {:?}", received.clone());
                                    break;
                                }
                            }
    
                            Err(err) => panic!(format!("{}", err))
                        }
                    }
                });
            }
    
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {  }
    
            Err(err) => panic!(format!("{}", err))
        }
    
        match client.read_commmand() {
    
            Ok(readed) => {
                match readed {
    
                    Some(received) => {
                        println!("CLIENT <- {:?}", received);
                        return;
                    }
    
                    None => {}
                }
            }
    
            Err(err) => {
                match err {
                    Error::Io(io_err) if io_err.kind() == io::ErrorKind::WouldBlock => {}
                    
                    _ => panic!(format!("{}", err))
                }
            }
        }
    }
}
```

License
-------
loco-protocol is following MIT License.