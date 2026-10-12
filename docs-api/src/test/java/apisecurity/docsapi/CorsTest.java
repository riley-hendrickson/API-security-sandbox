package apisecurity.docsapi;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CorsTest
{

    static final String BFF_ORIGIN  = "http://localhost:8081";
    static final String EVIL_ORIGIN = "http://evil.example";

    @Autowired MockMvc mockMvc;

    // What the browser sends before a cross-origin request with an Authorization header
    private static MockHttpServletRequestBuilder preflight(String origin, String method, String requestHeaders)
    {
        return options("/documents")
                .header(HttpHeaders.ORIGIN, origin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, method)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, requestHeaders);
    }

    // ---- preflights ----

    @Test
    void preflightFromBff_isApproved_withoutAToken() throws Exception
    {
        mockMvc.perform(preflight(BFF_ORIGIN, "GET", "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, BFF_ORIGIN))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, containsString("GET")))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                        containsStringIgnoringCase("Authorization")))
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS));
    }

    @Test
    void preflightFromUnknownOrigin_isRefused() throws Exception
    {
        mockMvc.perform(preflight(EVIL_ORIGIN, "GET", "Authorization"))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void preflightForUnlistedMethod_isRefused() throws Exception
    {
        mockMvc.perform(preflight(BFF_ORIGIN, "PATCH", "Authorization"))
                .andExpect(status().isForbidden());
    }

    @Test
    void preflightForUnlistedHeader_isRefused() throws Exception
    {
        mockMvc.perform(preflight(BFF_ORIGIN, "GET", "X-Sneaky-Header"))
                .andExpect(status().isForbidden());
    }

    @Test
    void preflightResult_isCacheable() throws Exception
    {
        mockMvc.perform(preflight(BFF_ORIGIN, "GET", "Authorization"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "3600"));
    }

    // ---- actual requests ----

    @Test
    void actualRequestFromBff_carriesAllowOriginHeader() throws Exception
    {
        mockMvc.perform(get("/documents").with(jwt())
                        .header(HttpHeaders.ORIGIN, BFF_ORIGIN))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, BFF_ORIGIN));
    }

    @Test
    void actualRequestFromUnknownOrigin_getsNoAllowOriginHeader() throws Exception
    {
        mockMvc.perform(get("/documents").with(jwt())
                        .header(HttpHeaders.ORIGIN, EVIL_ORIGIN))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }
}