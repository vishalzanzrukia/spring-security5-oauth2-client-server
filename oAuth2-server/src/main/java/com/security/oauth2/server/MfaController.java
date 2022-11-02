package com.security.oauth2.server;

import com.security.oauth2.server.util.Cache;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class MfaController {
    @GetMapping("/mfa")
    public ModelAndView mfaPage() {
        return new ModelAndView("mfa");
    }

    @PostMapping("/mfa")
    @PreAuthorize("hasRole('PRE_AUTH')")
    void mfaVerify(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = request.getParameter("token");
        String uuid = request.getParameter("uuid");
        if ("123456".equals(token)) {
            String redirectUrl = Cache.getOauthRequest(uuid).getRedirectUrl();
            Cache.removeCache(uuid);
            response.sendRedirect(redirectUrl);
        } else {
            String mfaUrl = "http://127.0.0.1:8081/mfa?uuid="+uuid+"&error=invalid";
            response.sendRedirect(mfaUrl);
        }

    }
}
