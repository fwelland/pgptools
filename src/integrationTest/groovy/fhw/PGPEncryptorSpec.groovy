package fhw

import spock.lang.*
import java.io.*
import java.nio.charset.StandardCharsets
import java.nio.*
import java.nio.file.*


class PGPEncryptorSpec
    extends Specification
{       
           
    
    def largeString = """
    ABCDEFGHIJKLMNOPQRSTUVWXYZ
    ABCDEFGHIJKLMNOPQRSTUVWXYZ
    ABCDEFGHIJKLMNOPQRSTUVWXYZ
    """
    
    
    def "spot test copy input to output"()
    {
        given: 
            def pgpe = new PGPEncryptor()
            InputStream inStream
            OutputStream outStream = new ByteArrayOutputStream()
            inStream = new ByteArrayInputStream(largeString.getBytes(StandardCharsets.UTF_8));
                    
        when: 
            pgpe.copyInputStreamToOutputStream(inStream, outStream)
                       
        then:
            largeString == outStream.toString()
        
    }
    
    def "spot check compress input stream"()
    {
        given:
            def pgpe = new PGPEncryptor()
            InputStream inStream
            OutputStream outStream = new ByteArrayOutputStream()
            inStream = new ByteArrayInputStream(largeString.getBytes(StandardCharsets.UTF_8));
            pgpe.clearInput = inStream
            
        when: 
            pgpe.compressInputStream()
            
        then: 
            //FWIW just check that there are compressed bytes, i guess. 
            pgpe.compressedInput
    }
    
    def "simple read public/encryption key spec"()
    {
        given:
            def pubKey = getClass().getResource("/dv-public-key.pgp")            
            def pgpe = new PGPEncryptor()           
            def keyInStream = new FileInputStream(new File(pubKey.toURI()))
            pgpe.publicEncryptionKeyStream = keyInStream
            
        when: 
            def pk = pgpe.readPublicKey()
            
        then: 
            pubKey
            keyInStream
            pk
            //dumpToScreen(keyInStream)
    }    
	
    
    def dumpToScreen(InputStream inStream)
    {
        try
        {
            InputStreamReader isr = new InputStreamReader(inStream)
            int data = isr.read();
            while (data != -1) 
            {
                System.out.print((char) data);
                data = isr.read();
            }
        } 
        catch (IOException e)
        {
            e.printStackTrace();
        }
        return true
    }
    
    @Ignore
    def "spot check compress input stream via simple file"()
    {
        given:
            def pgpe = new PGPEncryptor()
            InputStream inStream
            OutputStream outStream = new ByteArrayOutputStream()
            inStream = new ByteArrayInputStream(largeString.getBytes(StandardCharsets.UTF_8));
            pgpe.clearInput = inStream
                    
        when: 
            pgpe.compressInputStream()
            Path p = Paths.get("/tmp/derp.zip")
            Files.write(p, pgpe.compressedInput)
            
        then: 
            //FWIW just check that there are compressed bytes, i guess. 
            pgpe.compressedInput
                        
    }
    
    @IgnoreRest
    def "spot check encrypt"()
    {
        given:
            def encryptionKey = getClass().getResource("/ls-public-key.asc")
            def clearText = getClass().getResource("/message-from-dv-to-ls.txt")            
            def pgpe = new PGPEncryptor() 
            def keyInStream = new FileInputStream(new File(encryptionKey.toURI()))
            def clearInStream = new FileInputStream(new File(clearText.toURI()))
            pgpe.publicEncryptionKeyStream = keyInStream
            pgpe.clearInput = clearInStream
            pgpe.cypherOutput = new FileOutputStream("/tmp/something.gpg")
            
        when: 
            pgpe.encrypt()
            pgpe.cypherOutput.close()
            
        then: 
            println "then"
    }        
    
    
    def "call derp"()
    {
        given:
            def encryptionKey = getClass().getResource("/ls-public-key.asc")
            def keyInStream = new FileInputStream(new File(encryptionKey.toURI()))
            def pgpe = new PGPEncryptor()             
            pgpe.publicEncryptionKeyStream = keyInStream
            
        when: 
            pgpe.derp()
            
        then: 
            println "then"
    }           
}

