# Performance

Encryption and decryption speed

## 

SwiftHPKE's encryption and decryption performance was measured on a MacBook Pro 2024, Apple M3 chip.

The time to create a ``SwiftHPKE/Sender`` and ``SwiftHPKE/Recipient`` instance in base mode is shown in the table below,
depending on the KEM type - units are milliseconds.

| KEM        | Create Sender | Create Recipient |
|-----------:|--------------:|-----------------:|
| P256       | 5.1 mSec      | 4.2 mSec         |
| P384       | 13 mSec       | 10 mSec          |
| P521       | 28 mSec       | 23 mSec          |
| X25519     | 0.10 mSec     | 0.06 mSec        |
| X448       | 0.9 mSec      | 0.5 mSec         |

The encryption and decryption speed in base mode, once the `Sender` or `Recipient` instance is created,
is shown in the table below, depending on the AEAD type - units are megabytes / second.

| AEAD       | Encryption speed | Decryption speed |
|-----------:|-----------------:|-----------------:|
| AESGCM128  | 6000 MB/Sec      | 5600 MB/Sec      |
| AESGCM256  | 5600 MB/Sec      | 5000 MB/Sec      |
| CHACHAPOLY |  780 MB/Sec      |  790 MB/Sec      |
