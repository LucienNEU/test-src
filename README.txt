CS6740 Network Security Problem Set 02:Cryptography

1.Application of Cryptography -by Xiaozang Li

Algorithms: Using AES algorithm for encryption/decryption KEY_SIZE: 128bits (also can use 256bits)
            Using RSAwithMD5 algorithm for signature sign/verify processing KEY_SIZE: 1024bits

Detail: 1. this java program can using -g option to generate 1024bits RSA public,private key pair (both sender and receiver)
	2. Encryption
	2.1 Generate 128bits AES KEY to encryt the whole inputfile data. Mode:AES, ENCRYPT_MODE
	2.2 Use receiver_publicKey to encrypt AES 128bits key and add the encrypted key to the head of the encrypted data. Mode:RSA,WRAPPED_MODE
	2.3 Use sender_privateKey to sign the encrypted data(including encrypted AES Key). Mode:RSAwithMD5
	2.4 Combine Signature message with Encrypted data, saved as outputfile.
	3. Decryption
	3.1 Extract Signature message from inputfile.
	3.2 Use sender_publicKey to verify the signature. Mode:RSAwithMD5
	3.3 If verification succeed, continue for AES decrytion, otherwise pop up error message and exit.
	3.4 Extract encrypted AES KEY after the Signature message but ahead of the encypted file data.
	3.5 Use receiver_privateKey to decrypt AES key. Mode:RSA,UNWRAPPED_MODE
	3.6 Use decryped AES key to decrypt the encrypted file data and saved as outputfile. Mode:AES.DECRYPT_MODE
	    
Usage:fcrypt [option] [keyfile1] [keyfile2] [inputfile] [outputfile]
[option] -g, genearting 2 piars of public/private keys: sender public key file, sender private key file, receiver public key file, receiver private key file. Generate at current directory, named sender_privateKey.txt sender_publicKey.txt receiver_privateKey.txt receiver_publicKey.txt
        e.g. java -jar fcrypt.jar -g  
[option] -e, using keyfile1(public key) to encrypt inputfile, then using keyfile2(private key) to sign the whold inputfile, outputfile stores both signature messages and encryted data.
        e.g. java -jar fcrypt.jar -e receiver_publicKey.txt sender_privateKey.txt input_plaintext.txt output_ciphertext.txt
[option] -d, using keyfile2(public key) to verify the signature message, if succeed, using keyfiel1(private key) to decrypt the encrypted data.
        e.g. java -jar fcrypt.jar -d receiver_privateKey.txt sender_publicKey.txt output_ciphertext.txt outuput_pliantext.txt


