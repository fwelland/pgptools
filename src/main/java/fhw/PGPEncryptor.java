package fhw;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Iterator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
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

//        OutputStream    out,
//        String          fileName,
//        PGPPublicKey    encKey,
//        boolean         withIntegrityCheck            
    
    public void encrypt()
        throws IOException
    {
        


        compressInputStream();        
        PGPEncryptedDataGenerator encGen; 
        encGen = new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                            .setWithIntegrityPacket(includeIntegrityCheck)
                            .setSecureRandom(new SecureRandom()).setProvider("BC")
        );        
//        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
//
//        OutputStream cOut = encGen.open(out, compressedInput.length);
//
//        cOut.write(bytes);
//        cOut.close();        
    }
//
//            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
//                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
//                        .setWithIntegrityPacket(withIntegrityCheck)
//                        .setSecureRandom(new SecureRandom()).setProvider("BC"));
//
//            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
//
//            OutputStream cOut = encGen.open(out, compressedInput.length);
//
//            cOut.write(bytes);
//            cOut.close();
//        }
//        catch (PGPException e)
//        {
//            System.err.println(e);
//            if (e.getUnderlyingException() != null)
//            {
//                e.getUnderlyingException().printStackTrace();
//            }
//        }
//    }
//}

}



//    protected byte[] compressFile(String fileName, int algorithm) 
//        throws IOException
//    {
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
//        PGPUtil.writeFileToLiteralData(
//                comData.open(bOut),
//                PGPLiteralData.BINARY,
//                new File(fileName));
//        comData.close();
//        return bOut.toByteArray();
//    }    