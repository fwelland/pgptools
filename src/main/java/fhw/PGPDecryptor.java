package fhw;

import java.io.*;
import java.util.*;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
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
            PGPPublicKey pgpPubKey = null;
            PGPObjectFactory pgpFact;

            if(Objects.nonNull(signatureKeyStream))
            {

                pgpPubKey = PGPKeyUtil.readPublicKey(signatureKeyStream);
            }

            InputStream in = PGPUtil.getDecoderStream(cypherInput);
            PGPObjectFactory pgpObjFactory = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;
            Object o = pgpObjFactory.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList) o;
            }
            else
            {
                enc = (PGPEncryptedDataList) pgpObjFactory.nextObject();
            }

            //
            // find the secret key
            //

            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPublicKeyEncryptedData pbe = null;
            PGPPrivateKey sKey = null;
            while (sKey == null && it.hasNext())
            {
                pbe = it.next();
                sKey = findSecretKey(privateKeyInput, pbe.getKeyID(), privateKeyPassPhrase.toCharArray());
            }
            if (sKey == null)
            {
                throw new IllegalArgumentException("Secret key for message not found.");
            }
            InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
             pgpFact = new BcPGPObjectFactory(clear);

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

                InputStream inLd = ld.getDataStream();
                ops.init(
                   new BcPGPContentVerifierBuilderProvider(),
                   pgpPubKey);
                int ch;
                byte[] buf = new byte[1 << 16];
                while ((ch = inLd.read(buf)) > 0)
                {
                    ops.update(buf,0, ch);
                    getClearOutput().write(buf,0, ch);
                }

                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
                System.out.println("VERIFIED==========" + ops.verify(p3.get(0)));
            }
            else if(pgpObject instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) pgpObject;
                InputStream unc = ld.getInputStream();
                Streams.pipeAll(unc,  getClearOutput());

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


    public void setPrivateKeyInput(InputStream privateKeyInput)
    {
        this.privateKeyInput = privateKeyInput;
    }

    public void setPrivateKeyPassPhrase(String privateKeyPassPhrase)
    {
        this.privateKeyPassPhrase = privateKeyPassPhrase;
    }


    public void setSignatureKeyStream(InputStream signatureKeyStream)
    {
        this.signatureKeyStream = signatureKeyStream;
    }
}