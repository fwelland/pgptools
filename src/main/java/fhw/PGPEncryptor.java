package fhw;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.*;

public class PGPEncryptor
{
    private OutputStream cypherOutput;
    private InputStream clearInput;
    private InputStream publicEncryptionKeyStream;
    private byte[] compressedInput; 
    private Boolean includeIntegrityCheck = false; 
    
    
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
        copyInputStreamToOutputStream(clearInput,compressOut);       
        compressOut.close();
        squished.close();
        compressedInput  = squished.toByteArray();
    }
    
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
        throws Exception
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
    
    
    
    
    

}
