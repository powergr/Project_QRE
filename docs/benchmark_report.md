==========================================================================================
Starting Encryption Performance Benchmark 
==========================================================================================
Vault environment variables seem to be set.

--- System Information ---
Oqs Python Version Api             : 0.12.0
Python Version                     : 3.13.1
Platform Details                   : Windows-10-10.0.19045-SP0
Architecture                       : AMD64, 64bit
Cpu Model                          : Intel64 Family 6 Model 142 Stepping 10, GenuineIntel
Cpu Logical Cores                  : 4
Cpu Physical Cores                 : 2
Cpu Current Freq Mhz               : 2300
Cpu Max Freq Mhz                   : 2300
Total Ram Gb                       : 7.91 GB
Cryptography Version               : 45.0.3
Hvac Version                       : 2.3.0
Oqs Pip Installed Version          : oqs package not found
Psutil Version                     : 7.0.0
Openssl Version Note               : For linked OpenSSL, check 'openssl version' in your environment.
--- End System Information ---


==========================================================================================
Benchmark Report (Target < 100ms per operation)
==========================================================================================
Data Size: 1 MB
Iterations per operation: 100
Target Performance: < 100 ms
------------------------------------------------------------------------------------------
| Operation                                          |   Avg Time (ms) |    Std Dev (ms) | Status   |
|----------------------------------------------------|-----------------|-----------------|----------|
| Parallel Encrypt (Vault, Concurrent AES, 1MB)      |          26.509 ms |           7.465 ms | PASSED   |
| Parallel Decrypt (Vault, C1 path, 1MB)             |          21.336 ms |           9.766 ms | PASSED   |
| Layered Encrypt (Vault, 1MB)                       |          22.104 ms |           8.534 ms | PASSED   |
| Layered Decrypt (Vault, 1MB)                       |          22.627 ms |           7.409 ms | PASSED   |
|----------------------------------------------------|-----------------|-----------------|----------|
------------------------------------------------------------------------------------------

All operations met the performance target!

Benchmark finished.
Reminder: liboqs C library version (often shown in UserWarnings) is also relevant for performance.

Software Versions

Python: 3.13.1
OS: Windows 10 (10.0.19045)
cryptography: 45.0.3
hvac: 2.3.0
oqs (Python wrapper API): 0.12.0
liboqs C Library: Note the 0.13.1-dev (from UserWarning, if it appeared during these runs or previous ones – it seems it didn't in this specific benchmark output, which is interesting and good if it means the versions are now considered compatible enough by the wrapper).
psutil: 7.0.0
OpenSSL: Advise to check openssl version in the relevant build/run environment.

Optimizations Section

Mentioned that AES operations leverage hardware acceleration (AES-NI) via the cryptography library's OpenSSL backend.
State that parallel_encrypt_vault was implemented using concurrent.futures.ThreadPoolExecutor to run the two AES encryption paths concurrently.