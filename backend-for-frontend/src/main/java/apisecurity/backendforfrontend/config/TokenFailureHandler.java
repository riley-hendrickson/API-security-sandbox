package apisecurity.backendforfrontend.config;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class LogoutExceptionHandler
{
    @ExceptionHandler({OAuth2AuthorizationException.class, ClientAuthorizationRequiredException.class})
    public ResponseEntity<Void> handleTokenExpiredOrRevoked(Exception e)
    {
        HttpSession session = request.getSession(false)
    }
}
