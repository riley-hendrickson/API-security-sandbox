package apisecurity.backendforfrontend.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class TokenFailureHandler
{
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

    @ExceptionHandler(OAuth2AuthorizationException.class)
    public ResponseEntity<Void> handleTokenExpiredOrRevoked(HttpServletRequest request,
                                                            HttpServletResponse response,
                                                            Authentication authentication)
    {
        logoutHandler.logout(request, response, authentication);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
