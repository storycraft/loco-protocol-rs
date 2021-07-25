# loco-protocol - Loco protocol implementation

Open source Loco protocol implementation made with rust

## Specification
### Command
| name      | size              |
|-----------|-------------------|
| header    | (Header) 18 bytes |
| data_size | 4 bytes           |
| data      | header.data_size  |

#### Header
| name      | size     |
|-----------|----------|
| id        | 4 bytes  |
| status    | 2 bytes  |
| name      | 11 bytes |
| data_type | 1 bytes  |

### Secure data
| name           | size               |
|----------------|--------------------|
| header         | (Header) 20 bytes  |
| encrypted data | header.size - 16   |

#### Header
| name      | size     |
|-----------|----------|
| size      | 4 bytes  |
| iv        | 16 bytes |

#### Handshake
| name             | size       |
|------------------|------------|
| key size         | 4 bytes    |
| key_encrypt_type | 4 bytes    |
| encrypt_type     | 4 bytes    |
| key              | 256 bytes  |

Note: current implementation only supports RSA-AES

## WASM support
To build with WASM target `wasm32-unknown-unknown`, you must enable `wasm` feature.

## License
-------
```
MIT License

Copyright (c) 2021 storycraft

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```