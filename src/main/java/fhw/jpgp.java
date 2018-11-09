package fhw;

import java.io.*;
import java.util.concurrent.Callable;
import picocli.*;
import picocli.CommandLine.*;

@Command(description = "simple gpg like tool", name = "jpgp", mixinStandardHelpOptions = true)
public class jpgp
    implements Callable<Void> 
{
    
    @Option(names = {"-d", "--decrypt"}, description = "decrypt input file (one of encrypt OR decrypt required)", defaultValue = "false")
    private boolean doDecrypt; 
    
    @Option(names = {"-e", "--encrypt"}, description = "encrypt input file (one of encrypt OR decrypt required)", defaultValue = "false")
    private boolean doEncrypt;     

    @Option(names = {"-i", "--input-file"}, description = "file containing clear or cypher text to operate on", required = true)
    private String inputFile; 
        
    @Option(names = {"-k", "--key"}, description = "file containing the key to use for either encrypt/decrypt", required = true)
    private String keyFile;
    
    @Option(names = {"-o", "--output-file"}, description = "file to write encrypt/decrypt data to")
    private String outputFile;    
    
    @Option(names = {"-p", "--passphrase"}, description = "secret password or phrase")
    private String passPhrase;        
    
    public static void main(String args[])
        throws Exception
    {
        CommandLine.call(new jpgp(), args);
    }

    private FileInputStream inStream; 
    private FileOutputStream outStream; 
    private FileInputStream keyInStream; 
    
    @Override
    public Void call()
        throws Exception
    {        
        if(doDecrypt && doEncrypt)
        {
            throw new IllegalArgumentException("Only ONE of encrypt or decrypt should be specified");
        }
        else if(!doDecrypt && !doEncrypt)
        {   
            throw new IllegalArgumentException("EITHER encrypt OR decrypt must be specified");            
        }
        else
        {
            inStream = new FileInputStream(inputFile); 
            outStream = new FileOutputStream(outputFile, false);
            keyInStream = new FileInputStream(keyFile);
            
            if(doDecrypt)
            {
                decrypt();
            }
            else if(doEncrypt)
            {
                encrypt(); 
            }
            inStream.close(); 
            outStream.close();
            keyInStream.close();
        }
        return((Void)null);
    }
    
    private void decrypt()
            throws PGPOperationException, IOException
    {
        PGPDecryptor pgp = new PGPDecryptor(); 
        pgp.setClearOutput(outStream);
        pgp.setCypherInput(inStream);
        pgp.setPrivateKeyInput(keyInStream);
        pgp.setPrivateKeyPassPhrase(passPhrase);
        pgp.decrypt();        
    }
    
    private void encrypt()
        throws PGPOperationException, IOException            
    {
        PGPEncryptor pgp = new PGPEncryptor(); 
        pgp.setPublicEncryptionKeyStream(keyInStream);
        pgp.setClearInput(inStream);
        pgp.setCypherOutput(outStream);        
        pgp.encrypt();
    }
}
