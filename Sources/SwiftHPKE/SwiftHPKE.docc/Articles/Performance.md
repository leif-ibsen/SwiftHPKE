# Performance

Encryption and decryption speed

## 

SwiftHPKE's encryption and decryption performance was measured on an iMac 2021, Apple M1 chip.

The time to create a ``SwiftHPKE/Sender`` and ``SwiftHPKE/Recipient`` instance in base mode is shown in the table below,
depending on the KEM type - units are milliseconds.

| KEM        | Sender        | Recipient   |
|-----------:|--------------:|------------:|
| P256       | 7 mSec        | 6 mSec      |
| P384       | 20 mSec       | 17 mSec     |
| P521       | 46 mSec       | 39 mSec     |
| X25519     | 0.14 mSec     | 0.09 mSec   |
| X448       | 1.1 mSec      | 0.5 mSec    |

The encryption and decryption speed in base mode, once the `Sender` or `Recipient` instance is created,
is shown in the table below, depending on the AEAD type - units are MBytes / Sec.

| AEAD       | Encryption speed                  | Decryption speed                 |
|-----------:|----------------------------------:|---------------------------------:|
| AESGCM128  | 3500 MB/Sec (0.91 cycles / byte)  | 3340 MB/Sec (0.96 cycles / byte) |
| AESGCM256  | 3640 MB/Sec (0.88 cycles / byte)  | 3630 MB/Sec (0.88 cycles / byte) |
| CHACHAPOLY |  555 MB/Sec (5.8 cycles / byte)   |  557 MB/Sec (5.7 cycles / byte)  |
