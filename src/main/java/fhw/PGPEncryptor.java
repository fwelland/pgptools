package fhw;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.test.UncloseableOutputStream;

public class PGPEncryptor
{
    private OutputStream cypherOutput;
    private InputStream clearInput;
    private InputStream publicEncryptionKeyStream;
    private InputStream privateSignatureKeyStream;
    private String privateKeyPassPhrase;
    private Boolean includeIntegrityCheck = true;
    private PGPSignatureGenerator signatureGenerator;

    public void setPrivateKeyPassPhrase(String privateKeyPassPhrase)
    {
        this.privateKeyPassPhrase = privateKeyPassPhrase;
    }


    public void setPrivateSignatureKeyStream(InputStream privateSignatureKeyStream)
    {
        this.privateSignatureKeyStream = privateSignatureKeyStream;
    }

    public PGPEncryptor()
    {

    }


    protected void initSignatureGenerator()   throws IOException, PGPException{
        signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.RSA_GENERAL, PGPUtil.SHA1));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, PGPKeyUtil.readPrivateKey( privateSignatureKeyStream, privateKeyPassPhrase));
    }


    protected void compressInputStreamWithSignature(OutputStream bOut)
       throws IOException, PGPException
    {
        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
           PGPCompressedData.ZIP);
        try (
           BCPGOutputStream bcOut = new BCPGOutputStream(
              cGen.open(new UncloseableOutputStream(bOut)))
        )
        {

            initSignatureGenerator();
            signatureGenerator.generateOnePassVersion(false).encode(bcOut);
            PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();

            Date testDate = new Date((System.currentTimeMillis() / 1000)
               * 1000);
               OutputStream lOut = lGen.open(
                  new UncloseableOutputStream(bcOut),
                  PGPLiteralData.BINARY,
                  "_CONSOLE",
                  testDate, new byte[1 << 16]);


                byte[] buf = new byte[1 << 16];
                int ch;
                while ((ch = clearInput.read(buf)) > 0)
                {
                    lOut.write(buf,0, ch);
                    signatureGenerator.update(buf,0, ch);
                }
                lGen.close();
                signatureGenerator.generate().encode(bcOut);
                cGen.close();
                Arrays.fill(buf, (byte)0);
                clearInput.close();
        }
    }

    protected void compressInputStream(OutputStream bOut)
        throws IOException
    {
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        try( OutputStream compressOut = comData.open(bOut))
        {
            PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
            try(OutputStream pOut = lData.open(
               compressOut,                // the compressed output stream
               PGPLiteralData.BINARY,
               "fileName",                 // "filename" to store _CONSOLE
               clearInput.available(),   // length of clear data
               new Date()))
            {                // current time
                Streams.pipeAll(clearInput,  compressOut);
                compressOut.close();
            }
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


    public void setClearInput(InputStream clearInput)
    {
        this.clearInput = clearInput;
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
        PGPPublicKey encryptionKey = PGPKeyUtil.readPublicKey(publicEncryptionKeyStream);
        long kid = encryptionKey.getKeyID();
        System.out.println("this encryption key id:  " + get8DigitKeyId(kid));
    }



    public void encrypt()
         throws IOException, PGPOperationException
    {
        long start = System.currentTimeMillis();
        try
        {
            Security.addProvider(new BouncyCastleProvider());

            PGPEncryptedDataGenerator encGen;
            encGen = new PGPEncryptedDataGenerator(
                            new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                                .setWithIntegrityPacket(includeIntegrityCheck)
                                .setSecureRandom(new SecureRandom()).setProvider("BC")
            );
            PGPPublicKey encryptionKey = PGPKeyUtil.readPublicKey(publicEncryptionKeyStream);
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

            OutputStream cOut = encGen.open(cypherOutput,new byte[1 << 16]);

            if(Objects.nonNull(privateKeyPassPhrase) && Objects.nonNull(privateSignatureKeyStream)){
                compressInputStreamWithSignature(cOut);
            }
            else
            {
                compressInputStream(cOut);
            }
            cOut.close();
        }
        catch(PGPException e)
        {
            throw new PGPOperationException(e.getMessage(), e);
        }
        finally
        {
            System.out.println(String.format("Encryption duration is %d s",(System.currentTimeMillis()-start)/1000));
        }
    }

}
