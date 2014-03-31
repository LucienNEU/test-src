import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class fcrypt 
{
	public static void main(String[] args) throws Exception
	{
		// TODO Auto-generated method stub
		
		if(args.length == 0)
		{
			//Usage notification
			System.out.println("Usage:[option] [destination_public_key_filename] [ender_private_key_filename] [input_plaintext_file] [output_ciphertext_file]");
			System.out.println("More details see README file :)");
		    System.exit(1);
		}
		else if(args[0].equals("-g"))
		{
			//-g option:
			//@ generate RSA public_private Key pairs
			//@ and store in current directory
			// key length can be 1024 or 2048 bits 
			public_private_key_generator("RSA",1024);
			System.exit(0);
		}
		else if(args[0].equals("-e"))
		{
			//-e option:
			//@ Using AES algorithm to do encryption
			//@ AES is used to encrypt the whole plaintext file
			//@ it is much faster than asymmetric encryption like RSA
			data_encryption("AES","RSA",args[1],args[3]);
			
			//@ and Signature algorithm is using MD5withRSA
			//@ so efficient
			data_signature("MD5withRSA",args[2],args[4]);
			System.exit(0);
		}
		else if(args[0].equals("-d"))
		{
			//-d option:
			//@ decryption of ciphertext data
			//@ Fisrt, Verify the signature ahead of the encryption file
			//@ if verification failed, it will not continue to the decryption step
			data_signature_verify("MD5withRSA",args[2],args[3]);
			
			//@ after the signature verification, it will
			//@ focus on the decryption work, using the AES at the head of the file,
			//@ which is also encrypted by the RSA algorithm
			data_decryption("AES","RSA",args[1],args[3],args[4]);
			System.exit(0);
		}
		else
		{
			// invalid inputs notification
		 	System.out.println("Invalid Input.");
		 	System.exit(1);
		}
		
		
	}

	private static void data_decryption(String symmetric_algorithm_type, String asymmetric_algorithm_type, String destination_private_key, String input_ciphertext_file, String output_plaintext_file) throws Exception 
	{
		// TODO Auto-generated method stub
		// Ignore the already verified signature messages.
		DataInputStream input_file = new DataInputStream(new FileInputStream(input_ciphertext_file));
		int s_length = input_file.readInt();
		byte[] s_sig = new byte[s_length];
		input_file.read(s_sig,0,s_length); 
        
		// Extract the wrapped AES Key
		int key_length = input_file.readInt();
		byte[] wrappedKey = new byte[key_length];
		input_file.read(wrappedKey,0,key_length);
		
		// Read destination_private_key from file and prepare for decrypt wrapped AES Key		
		ObjectInputStream input = new ObjectInputStream(new FileInputStream(destination_private_key));
		RSAPrivateKey receiver_privateKey = (RSAPrivateKey) input.readObject();
		input.close();
        
		// AES key decryption initialization in RSA UNWRAP_MODE
		Cipher rsa_cipher = Cipher.getInstance(asymmetric_algorithm_type);
		rsa_cipher.init(Cipher.UNWRAP_MODE,receiver_privateKey);
		
		// Great! AES Key decrypted! 
		Key AES_Key = rsa_cipher.unwrap(wrappedKey, symmetric_algorithm_type, Cipher.SECRET_KEY);
		
		// Start Ciphertext decrytion and write the pliantext to outpu_plaintext_file
		FileOutputStream fos = new FileOutputStream(output_plaintext_file);
        
		//Using the decrypted AES key to initialize ciphertext data DECRYPT_MODE
		Cipher aes_cipher = Cipher.getInstance(symmetric_algorithm_type);
		aes_cipher.init(Cipher.DECRYPT_MODE, AES_Key);
        
		//DATA Decryption 
		CipherInputStream cis = new CipherInputStream(input_file,aes_cipher);
        
		byte[] buffer = new byte[1024];
		int i = cis.read(buffer);
		while(i != -1)
		{
			fos.write(buffer,0,i);
			i = cis.read(buffer);       	
		}
        
		cis.close();
		fos.close();
		// result messages pop up 
		System.out.println("Decryption OK.");
	}
	
	private static void data_signature_verify(String signature_algorithm_type, String sender_public_key, String input_ciphertext_file) throws Exception 
	{
		// TODO Auto-generated method stub
		
		//open ciphertext_file for signature verification
		DataInputStream input_file = new DataInputStream(new FileInputStream(input_ciphertext_file));
        
		//extract the signatrue message at the head of ciphertext file
		int s_length = input_file.readInt();
		byte[] sig = new byte[s_length];
		input_file.read(sig,0,s_length); 
        
		//take sender_public_key from current directory
		ObjectInputStream input = new ObjectInputStream(new FileInputStream(sender_public_key));
		RSAPublicKey sender_publicKey = (RSAPublicKey) input.readObject();
		input.close();
		
		//@ and set up the verification initialization
		Signature signature = Signature.getInstance(signature_algorithm_type);
		signature.initVerify(sender_publicKey);
		
		// Signature verification 
		byte[] buffer = new byte[1024];
		       
		int i = input_file.read(buffer);
		while( i!= -1 )
		{
			signature.update(buffer);	
			i = input_file.read(buffer);
		}
        
		input_file.close();
		
		if(!signature.verify(sig))
		{
		  System.out.println("signature verification failed.");
		  System.exit(1);
		}
		else
		{
		  System.out.println("signature verification OK.");
		}
	}

	private static void data_signature(String signature_algorithm_type, String sender_private_key, String output_ciphertext_file) throws Exception
	{
		// TODO Auto-generated method stub
		// the whole encryted data exits at ./temp.txt file
		//@ use these data to do the RSA signature 
		FileInputStream fis = new FileInputStream("./temp.txt");
 

		// Read the sender_privateKey from files to do signature sign
		ObjectInputStream input = new ObjectInputStream(new FileInputStream(sender_private_key));
		RSAPrivateKey sender_privateKey = (RSAPrivateKey) input.readObject();
		input.close();
         
		// signature initialization
		Signature signature = Signature.getInstance(signature_algorithm_type);
		signature.initSign(sender_privateKey);
		
		// RSA signature signing
		byte[] buffer = new byte[1024];
		int i;
		while(( i = fis.read(buffer))!= -1)
		{
			signature.update(buffer);
		}
		byte[] sig = signature.sign();
		
		// signing Succeed message pop up
		System.out.println("signature Finished.");
		fis.close(); 
		
		fis = new FileInputStream("./temp.txt");
		// the signature message will be wrote to the head of output file
		//@ then coming the encrypted data from ./temp.txt
		//@ after the combination, ./temp.txt will be deleted 
		DataOutputStream output_file = new DataOutputStream(new FileOutputStream(output_ciphertext_file));
		
		output_file.writeInt(sig.length);
		output_file.write(sig);
		
		while((i = fis.read(buffer,0,buffer.length) )!= -1)
		{
			output_file.write(buffer,0,i);
		}
      
		output_file.close();
		fis.close();
        
		// delete ./temp.txt file
		boolean delete =new File("./temp.txt").delete();
		if(!delete)
		{
			System.out.println("temp_file delete failed.");
		}
		
	}

	private static void data_encryption(String symmetric_algorithm_type,String asymmetric_algorithm_type,String destination_public_key, String input_plaintext_file) throws Exception 
	{
		// TODO Auto-generated method stub
		
		//Generate AES Key & initialized as 128 bits
		KeyGenerator k = KeyGenerator.getInstance(symmetric_algorithm_type);
		k.init(128);
		SecretKey AES_Key = k.generateKey();
				
				
		// Read destination_publicKey from File and used to encrypt the AES Key
		ObjectInputStream input = new ObjectInputStream(new FileInputStream(destination_public_key));
		RSAPublicKey receiver_publicKey = (RSAPublicKey) input.readObject();
		input.close();
	
				
		// encrypt the AES 128 bits using WRAP_MODE
		Cipher rsa_cipher = Cipher.getInstance(asymmetric_algorithm_type);
		rsa_cipher.init(Cipher.WRAP_MODE, receiver_publicKey);
		byte[] wrappedKey = rsa_cipher.wrap(AES_Key);
				
		// the encrypted AES key will be wrote to the head of the ciphertext data
		//@ first the encrypted data would be in ./temp.txt file
		//@ after the signature step, the whold contents of ./temp.txt file would be move to ./signature file
		//@ and the RSA signature is at the head of all the encryption data
		DataOutputStream output_file = new DataOutputStream(new FileOutputStream("./temp.txt"));
		output_file.writeInt(wrappedKey.length);
		output_file.write(wrappedKey);
				
		// Step up AES encrypt mode and begin AES encryption
		Cipher aesCipher = Cipher.getInstance(symmetric_algorithm_type);
		aesCipher.init(Cipher.ENCRYPT_MODE,AES_Key);
		        
		FileInputStream fis = new FileInputStream(input_plaintext_file);
		CipherInputStream cis = new CipherInputStream(fis,aesCipher);
		        
		byte[] buffer = new byte[1024];
		int i = cis.read(buffer);
		while(i != -1)
		{
			output_file.write(buffer,0,i);
		    i = cis.read(buffer);
		}
		        
		 cis.close();
		 fis.close();
		 output_file.close();	
		 // Succeed message pop up
		 System.out.println("encyption Finished.");
	}

	private static void public_private_key_generator(String Algorithm_type, int key_length) throws Exception
{
		// TODO Auto-generated method stub
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(Algorithm_type);
		keygen.initialize(key_length);
		KeyPair k1 = keygen.generateKeyPair();
		KeyPair k2 = keygen.generateKeyPair();
		PublicKey sender_publicKey = k1.getPublic();
		PrivateKey sender_privateKey = k1.getPrivate();
		PublicKey receiver_publicKey = k2.getPublic();
		PrivateKey receiver_privateKey = k2.getPrivate();
		
		//2 pairs of public_private key will be generated (sender's, receiver's)
		//naming: sender_privateKey.txt
		//@       sender_publicKey.txt
		//@       receiver_privateKey.txt
		//@       receiver_publicKey.txt
		//
		ObjectOutputStream output = new ObjectOutputStream(new FileOutputStream("./sender_privateKey.txt"));
		output.writeObject(sender_privateKey);
		output.close();
		
		output = new ObjectOutputStream(new FileOutputStream("./sender_publicKey.txt"));
		output.writeObject(sender_publicKey);
		output.close();
		
		output = new ObjectOutputStream(new FileOutputStream("./receiver_privateKey.txt"));
		output.writeObject(receiver_privateKey);
		output.close();
		
		output = new ObjectOutputStream(new FileOutputStream("./receiver_publicKey.txt"));
		output.writeObject(receiver_publicKey);
		output.close();
		
		System.out.println("public_private_keys generated.");
	}
}
