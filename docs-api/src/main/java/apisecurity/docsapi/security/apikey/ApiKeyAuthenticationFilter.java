package apisecurity.docsapi.security.apikey;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ApiKeyAuthenticationFilter extends OncePerRequestFilter
{
    private final AuthenticationManager authenticationManager;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    public ApiKeyAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint)
    {
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        String userApiKey = request.getHeader("X-API-Key");
        if(userApiKey == null || userApiKey.isBlank())
        {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityContextHolderStrategy contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        try
        {
            Authentication authentication = authenticationManager.authenticate(ApiKeyAuthenticationToken.unauthenticated(userApiKey));

            SecurityContext newSecurityContext = contextHolderStrategy.createEmptyContext();
            newSecurityContext.setAuthentication(authentication);
            contextHolderStrategy.setContext(newSecurityContext);
        }
        catch(AuthenticationException e)
        {
            contextHolderStrategy.clearContext();
            authenticationEntryPoint.commence(request, response, e);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
