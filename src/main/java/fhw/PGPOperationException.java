package fhw;

public class PGPOperationException
    extends Exception
{
    public PGPOperationException(String message)
    {
        super(message);
    }

    public PGPOperationException(String message,Exception underlying)
    {
        super(message, underlying);
    }
}
