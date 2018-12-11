package fhw;

import java.io.*;
import java.util.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.*;
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
            PGPPublicKey pgpPubKey = null;

            if(Objects.nonNull(signatureKeyStream))
            {

                pgpPubKey = PGPKeyUtil.readPublicKey(signatureKeyStream);
            }

            PGPPrivateKey        pgpPrivKey =  PGPKeyUtil.readPrivateKey(privateKeyInput, privateKeyPassPhrase);

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