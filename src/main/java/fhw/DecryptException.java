package fhw;

public class DecryptException
    extends Exception
{
    public DecryptException(String message)
    {
        super(message);
    }

    public DecryptException(String message,Exception underlying)
    {
        super(message, underlying);
    }
}
