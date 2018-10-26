package fhw;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
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
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

public class PGPEncryptor
{
    private OutputStream cypherOutput;
    private InputStream clearInput;
    private InputStream publicEncryptionKeyStream;
    private byte[] compressedInput; 
    
    public PGPEncryptor()
    {

    }
   
    protected PGPPublicKey readPublicKey(InputStream input) 
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
        copyInputStreamToOutputStream(clearInput,squished);
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
}
    
//    private static void pipeFileContents(File file, OutputStream pOut, byte[] buf)
//        throws IOException
//    {
//        FileInputStream in = new FileInputStream(file);
//        try
//        {
//            int len;
//            while ((len = in.read(buf)) > 0)
//            {
//                pOut.write(buf, 0, len);
//            }
//
//            pOut.close();
//        }
//        finally
//        {
//            Arrays.fill(buf, (byte)0);
//            try
//            {
//                in.close();
//            }
//            catch (IOException ignored)
//            {
//                // ignore...
//            }
//        }
//    }    
       
//  public void encrypt(
//        OutputStream    out,
//        String          fileName,
//        PGPPublicKey    encKey,
//        boolean         withIntegrityCheck)
//        throws IOException, NoSuchProviderException
//    {
//        try
//        {
//            //byte[] bytes = compressFile(fileName, CompressionAlgorithmTags.ZIP);
//            compressInputStream();
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