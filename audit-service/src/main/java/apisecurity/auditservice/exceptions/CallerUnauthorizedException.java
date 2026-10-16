package apisecurity.auditservice.Exceptions;

public class CallerUnauthorizedException extends RuntimeException {
  public CallerUnauthorizedException(String message) {
    super(message);
  }
}
