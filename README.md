# AES
AES encryption algorithm written in Functional Java


Usage: aes (-e | -d) [-hV] [--IV=TEXT] -k=KEY [-m=<mode>] -t=TEXT <br/>
Encrypt or decrypt file using Advanced Encryption Standard <br/>
&nbsp;&nbsp;&nbsp;&nbsp;-d                  Decrypt text <br/>
&nbsp;&nbsp;&nbsp;&nbsp;-e                  Encrypt text <br/>
&nbsp;&nbsp;&nbsp;&nbsp;-h, --help          Show this help message and exit. <br/>
&nbsp;&nbsp;&nbsp;&nbsp;  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;--IV=TEXT       Initialization vector. Length needs to be 128 bits. <br/>
&nbsp;&nbsp;&nbsp;&nbsp;-k, --key=KEY       Secret key filename. Length needs to be 128, 192 or 256 bits.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;-m, --mode=<mode>   ECB or CBC mode <br/>
&nbsp;&nbsp;&nbsp;&nbsp;-t, --text=TEXT     Plaintext or ciphertext filename.<br/>
&nbsp;&nbsp;&nbsp;&nbsp;-V, --version       Print version information and exit. <br/>

Encrypted files will have the file name: <inputfilename>.enc <br/>
Decrypted files will have extension .dec
