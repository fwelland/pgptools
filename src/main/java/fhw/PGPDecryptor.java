package fhw;

import java.io.*;
import java.security.Security;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

public class PGPDecryptor
{

    private InputStream cypherInput;
    private OutputStream clearOutput;
    private InputStream privateKeyInput;
    private InputStream signatureKeyStream;
    private String privateKeyPassPhrase;

    public PGPDecryptor()
    {

    }



    public void decrypt() throws PGPOperationException, IOException
    {

        long startTime = System.currentTimeMillis();
        try
        {
            //
            // Read the public key
            //

            JcaPGPObjectFactory    pgpFact;
            PGPPublicKeyRing pgpPub = null;

            if(Objects.nonNull(signatureKeyStream))
            {
                pgpFact = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(
                   signatureKeyStream));
                 pgpPub = (PGPPublicKeyRing) pgpFact.nextObject();
            }

            PGPSecretKeyRing    sKey = new PGPSecretKeyRing(PGPUtil.getDecoderStream(privateKeyInput), new BcKeyFingerprintCalculator());
            PGPPrivateKey        pgpPrivKey = sKey.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(privateKeyPassPhrase.toCharArray()));


            //
            // signed and encrypted message
            //
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(cypherInput);

            PGPEncryptedDataList encList = (PGPEncryptedDataList)pgpF.nextObject();

            PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData)encList.get(0);

            InputStream clear = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivKey));

            pgpFact = new JcaPGPObjectFactory(clear);

            Object pgpObject = pgpFact.nextObject();
            if(pgpObject instanceof PGPCompressedData)
            {
                PGPCompressedData c1 = (PGPCompressedData) pgpObject;
                pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
                pgpObject = pgpFact.nextObject();

            }
            if(pgpObject instanceof PGPOnePassSignatureList)
            {
                PGPOnePassSignatureList p1 = (PGPOnePassSignatureList)pgpObject;
                PGPOnePassSignature ops = p1.get(0);

                PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();

                //ByteArrayOutputStream bOut = new ByteArrayOutputStream();

                InputStream inLd = ld.getDataStream();
                ops.init(
                   new BcPGPContentVerifierBuilderProvider(),
                   pgpPub.getPublicKey());
                int ch;

                while ((ch = inLd.read()) >= 0)
                {
                    ops.update((byte) ch);
                    getClearOutput().write(ch);
                }

                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
                System.out.println("VERIFIED==========" + ops.verify(p3.get(0)));
            }
            else if(pgpObject instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) pgpObject;
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0)
                {
                    getClearOutput().write(ch);
                }
            }

        }
        catch(IOException e)
        {
            throw e;
        }
        catch(PGPException pgpe)
        {
            throw new PGPOperationException(pgpe.getMessage(),pgpe);
        }
        finally
        {
            System.out.println(String.format("Time =%d s",
               (System.currentTimeMillis() - startTime) / 1000));
        }
    }



    protected PGPPrivateKey readPrivateKey(InputStream privateSignatureKeyStream,  char[] privateKeyPassPhrase)
       throws IOException, PGPException
    {
        PGPSecretKeyRing    sKey = new PGPSecretKeyRing( PGPUtil.getDecoderStream(privateSignatureKeyStream), new BcKeyFingerprintCalculator());
        PGPSecretKey pgpSecKey = sKey.getSecretKey();
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(privateKeyPassPhrase);
        PGPPrivateKey pk = pgpSecKey.extractPrivateKey(decryptor);
        return  pk;
    }




    protected PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
        throws IOException, PGPOperationException
    {
        try
        {
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), calculator);
            PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
            PGPPrivateKey pk = null; 
            if (pgpSecKey != null)
            {
                PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
                pk = pgpSecKey.extractPrivateKey(decryptor);            
            }
            return(pk);
        }
        catch(IOException ioe)
        {
            throw ioe; 
        }
        catch(PGPException pgpe)
        {
            throw new PGPOperationException(pgpe.getMessage(),pgpe);
        }
    }

    public InputStream getCypherInput()
    {
        return cypherInput;
    }

    public void setCypherInput(InputStream cypherInput)
    {
        this.cypherInput = cypherInput;
    }

    public OutputStream getClearOutput()
    {
        return clearOutput;
    }

    public void setClearOutput(OutputStream clearOutput)
    {
        this.clearOutput = clearOutput;
    }

    public InputStream getPrivateKeyInput()
    {
        return privateKeyInput;
    }

    public void setPrivateKeyInput(InputStream privateKeyInput)
    {
        this.privateKeyInput = privateKeyInput;
    }

    public String getPrivateKeyPassPhrase()
    {
        return privateKeyPassPhrase;
    }

    public void setPrivateKeyPassPhrase(String privateKeyPassPhrase)
    {
        this.privateKeyPassPhrase = privateKeyPassPhrase;
    }

    public InputStream getSignatureKeyStream()
    {
        return signatureKeyStream;
    }

    public void setSignatureKeyStream(InputStream signatureKeyStream)
    {
        this.signatureKeyStream = signatureKeyStream;
    }
}