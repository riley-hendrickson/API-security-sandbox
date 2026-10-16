package apisecurity.auditservice.Exceptions;

public class MalformedJwtException extends RuntimeException {
  public MalformedJwtException(String message) {
    super(message);
  }
}
