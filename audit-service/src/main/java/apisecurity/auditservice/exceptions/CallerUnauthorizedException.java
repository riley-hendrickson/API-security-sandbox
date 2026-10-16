package apisecurity.auditservice.exceptions;

public class CallerUnauthorizedException extends RuntimeException
{
    public CallerUnauthorizedException(String message)
    {
        super(message);
    }
}
