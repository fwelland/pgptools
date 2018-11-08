package fhw;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.concurrent.Callable;
import picocli.*;
import picocli.CommandLine.*;

@Command(description = "simple gpg like tool", name = "jpgp", mixinStandardHelpOptions = true)
public class jpgp
    implements Callable<Void> 
{
    
    @Option(names = {"-d", "--decrypt"}, description = "decrypt input file (one of encrypt OR decrypt required)", defaultValue = "true")
    private boolean doDecrypt; 
    
    @Option(names = {"-e", "--encrypt"}, description = "encrypt input file (one of encrypt OR decrypt required)", defaultValue = "false")
    private boolean doEncrypt;     

    @Option(names = {"-i", "--input-file"}, description = "file containing clear or cypher text to operate on", required = true)
    private String inputFile; 
        
    @Option(names = {"-s", "--secret-key"}, description = "file containing the secret key to use for encrypt/decrypt")
    private String secretKeyFile;
    
    @Option(names = {"-o", "--output-file"}, description = "file to write encrypt/decrypt data to")
    private String outputFile;    
    
    @Option(names = {"-p", "--passphrase"}, description = "secret password or phrase")
    private String passPhrase;        
    
    public static void main(String args[])
        throws Exception
    {
        CommandLine.call(new jpgp(), args);
    }

    @Override
    public Void call()
        throws Exception
    {        
        if(doDecrypt && doEncrypt)
        {
            throw new IllegalArgumentException("Only ONE of encrypt or decrypt should be specified");
        }
        else
        {
            if(doDecrypt)
            {
                FileInputStream inStream = new FileInputStream(inputFile); 
                FileInputStream inSecretKey = new FileInputStream(secretKeyFile);
                FileOutputStream outStream = new FileOutputStream(outputFile, false);                
                
                PGPDecryptor pgp = new PGPDecryptor(); 
                pgp.setClearOutput(outStream);
                pgp.setCypherInput(inStream);
                pgp.setPrivateKeyInput(inSecretKey);
                pgp.setPrivateKeyPassPhrase(passPhrase);
                pgp.decrypt();
            }
            else if(doEncrypt)
            {
                System.out.println("encrypt here...");
            }
            else
            {
                throw new IllegalArgumentException("EITHER encrypt OR decrypt must be specified");
            }
        }
        return((Void)null);
    }        
}
