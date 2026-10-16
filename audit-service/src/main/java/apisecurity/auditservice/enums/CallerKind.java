package apisecurity.auditservice.enums;

import apisecurity.auditservice.exceptions.CallerUnauthorizedException;
import org.springframework.security.oauth2.jwt.Jwt;

public enum CallerKind
{
    USER, SYSTEM;

    public static CallerKind from (Jwt jwt)
    {
        boolean hasSession = jwt.hasClaim("sid");
        boolean isServiceAccount = jwt.hasClaim("client_id");
        if(hasSession && !isServiceAccount) return USER;
        if(!hasSession && isServiceAccount) return SYSTEM;
        throw new CallerUnauthorizedException("Unrecognized caller");
    }
}
