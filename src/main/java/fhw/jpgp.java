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
    @Option(names = {"-i", "--input-file"}, description = "file containing clear or cypher text to operate on", required = true)
    private String inputFile; 
    
    @Option(names = {"-d", "--decrypt"}, description = "decrypt input file")
    private boolean doDecrypt = false; 
    
    @Option(names = {"-s", "--secret-key"}, description = "file containing the secret key to use for encrypt/decrypt", required = true)
    private String secretKeyFile;
    
    @Option(names = {"-o", "--output-file"}, description = "file to write encrypt/decrypt data to", required = true)
    private String outputFile;    
    
    @Option(names = {"-p", "--passphrase"}, description = "secret password or phrase", required = true)
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
        FileInputStream inStream = new FileInputStream(inputFile); 
        FileInputStream inSecretKey = new FileInputStream(secretKeyFile);
        FileOutputStream outStream = new FileOutputStream(outputFile, false);
        if(doDecrypt)
        {
            PGPDecryptor pgp = new PGPDecryptor(); 
            pgp.setClearOutput(outStream);
            pgp.setCypherInput(inStream);
            pgp.setPrivateKeyInput(inSecretKey);
            pgp.setPrivateKeyPassPhrase(passPhrase);
            pgp.decrypt();
        }
        else
        {
            System.out.println("I am sorry, I cannot do that. ");
        }

        return((Void)null);
    }        
}
