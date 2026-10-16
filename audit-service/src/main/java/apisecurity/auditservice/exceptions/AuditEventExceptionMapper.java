package apisecurity.auditservice.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class AuditEventExceptionMapper
{
    @ExceptionHandler(MalformedRequestException.class)
    public ResponseEntity<String> handleMalformedRequestException(MalformedRequestException e)
    {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Malformed request");
    }

    @ExceptionHandler(CallerUnauthorizedException.class)
    public ResponseEntity<String> handleCallerUnauthorizedException(CallerUnauthorizedException e)
    {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Caller not authorized to perform this action");
    }
}
