package fhw;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

public class PGPEncryptor
{
    private OutputStream cypherOutput;
    private InputStream clearInput;
    private InputStream publicEncryptionKeyStream;
    private byte[] compressedInput; 
    private Boolean includeIntegrityCheck = true; 
    
    
    public PGPEncryptor()
    {

    }
   
    protected PGPPublicKey readPublicKey() 
        throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(publicEncryptionKeyStream), 
            new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();
                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
                
    protected void compressInputStream()
        throws IOException
    {
        ByteArrayOutputStream squished = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compressOut = comData.open(squished);         
        byte[] clearInputAsBytes = clearInputToClearBytes();                         
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();        
        OutputStream pOut = lData.open( compressOut,                // the compressed output stream
                                        PGPLiteralData.BINARY, 
                                        "fileName",                 // "filename" to store
                                        clearInputAsBytes.length,   // length of clear data
                                        new Date());                // current time        
        ByteArrayInputStream bais = new ByteArrayInputStream(clearInputAsBytes); 
        copyInputStreamToOutputStream(bais,compressOut);       
        compressOut.close();
        squished.close();
        compressedInput  = squished.toByteArray();
    }
    
    
    protected byte[] clearInputToClearBytes()
        throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream(); 
        byte[] buffer = new byte[0xFFFF];
        for (int len = clearInput.read(buffer); len != -1; len = clearInput.read(buffer))
        { 
            os.write(buffer, 0, len);
        }
        return os.toByteArray();
    }

//
//Say, these 2 are about the same thing....could find way to refactore one 
//in terms of other. 
//    
    protected void copyInputStreamToOutputStream(InputStream source, OutputStream sink)
        throws IOException
    {
        byte[] buf = new byte[32768];
        int n;
        while ((n = source.read(buf)) > 0)
        {
            sink.write(buf, 0, n);
        }
    }    

    public OutputStream getCypherOutput()
    {
        return cypherOutput;
    }

    public void setCypherOutput(OutputStream cypherOutput)
    {
        this.cypherOutput = cypherOutput;
    }

    public InputStream getClearInput()
    {
        return clearInput;
    }

    public void setClearInput(InputStream clearInput)
    {
        this.clearInput = clearInput;
    }

    public InputStream getPublicEncryptionKeyStream()
    {
        return publicEncryptionKeyStream;
    }

    public void setPublicEncryptionKeyStream(InputStream publicEncryptionKeyStream)
    {
        this.publicEncryptionKeyStream = publicEncryptionKeyStream;
    }
    
    public String get8DigitKeyId(long kid)
    {
        String s = Long.toHexString(kid); 
        s = s.substring(s.length() -8);
        return(s.toUpperCase());
    }    
        
    protected void derp()
        throws Exception
    {
        PGPPublicKey encryptionKey = readPublicKey();
        long kid = encryptionKey.getKeyID();
        System.out.println("this encryption key id:  " + get8DigitKeyId(kid));
    }
    
    public void encrypt() 
         throws IOException, PGPOperationException
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());        
            compressInputStream();        
            PGPEncryptedDataGenerator encGen; 
            encGen = new PGPEncryptedDataGenerator(
                            new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                                .setWithIntegrityPacket(includeIntegrityCheck)
                                .setSecureRandom(new SecureRandom()).setProvider("BC")
            );        
            PGPPublicKey encryptionKey = readPublicKey();
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));
            OutputStream cOut = encGen.open(cypherOutput, compressedInput.length);
            cOut.write(compressedInput);
            cOut.close();        
        }
        catch(PGPException e)
        {
            throw new PGPOperationException(e.getMessage(), e); 
        }
    }
    
    
    
    
    

}
