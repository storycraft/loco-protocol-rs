# Loco protocol specification
## Command
| name      | size              |
|-----------|-------------------|
| header    | (Header) 18 bytes |
| data_size | 4 bytes           |
| data      | data_size         |

### Header
| name      | size     |
|-----------|----------|
| id        | 4 bytes  |
| status    | 2 bytes  |
| name      | 11 bytes |
| data_type | 1 bytes  |

## Secure data
| name           | size               |
|----------------|--------------------|
| header         | (Header) 20 bytes  |
| encrypted data | header.size - 16   |

### Header
| name      | size     |
|-----------|----------|
| size      | 4 bytes  |
| iv        | 16 bytes |

### Handshake
| name             | size       |
|------------------|------------|
| key size         | 4 bytes    |
| key_encrypt_type | 4 bytes    |
| encrypt_type     | 4 bytes    |
| key              | 256 bytes  |

## Networking
### Command
Stream: `Command #0 | Response command #0 | Broadcast command #1`

Client -> Command #0  
Server <- Command #0  
Server -> Response command #0  
Client <- Response command #0  
Server -> Broadcast command #1  
Client <- Broadcast command #1 

Command is likely unordered. To match response and request, use header id.

### Secure data
Stream: `Handshake | Secure data #0 | Secure data #1`

Client -> Handshake  
Client -> Secure data #0  
Server <- Secure data #0  
Server -> Secure data #1  
Client <- Secure data #1  