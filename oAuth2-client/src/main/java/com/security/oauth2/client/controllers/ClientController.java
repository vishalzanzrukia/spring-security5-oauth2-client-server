package com.security.oauth2.client.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.oauth2.client.util.PkceUtil;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Map;

@Controller
@SuppressWarnings("unused")
public class ClientController {

    @Value("${client-id}")
    private String clientId;

    @Value("${client-secret}")
    private String clientSecret;

    @Value("${handler-uri}")
    private String handlerUri;

    @Value("${server-uri}")
    private String serverUri;

    @Value("${server-secured-get-uri}")
    private String serverSecuredGetUri;

    private static final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    Environment environment;

    @SuppressWarnings("SameParameterValue")
    private boolean isMyProfileActive(String profile) {
        for (final String profileName : environment.getActiveProfiles()) {
            if (profile.equals(profileName)) return true;
        }
        return false;
    }

    private boolean isPkceProfileActive() {
        return isMyProfileActive("pkce");
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public ModelAndView login() {
        ModelAndView model;
        if (isPkceProfileActive()) {
            model = new ModelAndView("login-pkce");
            model.addObject("code_challenge", PkceUtil.codeChallenge);
        } else {
            model = new ModelAndView("login");
        }
        model.addObject("client_id", clientId);
        model.addObject("handler_uri", handlerUri);
        model.addObject("server_uri", serverUri);
        return model;
    }

    @RequestMapping(value = "/display", method = RequestMethod.GET)
    public ModelAndView displaySecureDetails(HttpServletRequest request) {
        return getDisplayModel(request);
    }

    @RequestMapping(value = "/authorized", method = RequestMethod.GET)
    public ModelAndView dataManagementHandler(@RequestParam("code") String code, HttpServletRequest httpServletRequest) {
        fetchTokenAndSetInSession(code, httpServletRequest);
        return new ModelAndView(new RedirectView("display"));
    }

    private ModelAndView getDisplayModel(HttpServletRequest request) {
        String token = (String) request.getSession().getAttribute("access_token");
        if (token == null) {
            return new ModelAndView(new RedirectView("login"));
        }

        // Use the access token for authentication
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        ResponseEntity<String> response = restTemplate.exchange(serverUri + serverSecuredGetUri, HttpMethod.GET, entity, String.class);

        ModelAndView model = new ModelAndView("details");
        model.addObject("details", response.getBody());

        //just for testing
        String refreshToken = (String) request.getSession().getAttribute("refresh_token");
        getTokenUsingRefreshToken(refreshToken);

        return model;
    }

    private void fetchTokenAndSetInSession(String code, HttpServletRequest httpServletRequest) {
        try {
            ResponseEntity<String> response;
            System.out.println("Authorization Ccode------" + code);

            HttpHeaders headers = new HttpHeaders();

            if (!isPkceProfileActive()) {
                String credentials = clientId + ":" + clientSecret;
                String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
                headers.add("Authorization", "Basic " + encodedCredentials);
            }


            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
            HttpEntity<String> request = new HttpEntity<>(headers);

            String access_token_url = serverUri + "/oauth2/token";
            access_token_url += "?code=" + code;
            access_token_url += "&client_id=" + clientId;
            access_token_url += "&grant_type=authorization_code";
            access_token_url += "&redirect_uri=http://127.0.0.1:8090/" + handlerUri;
            if (isPkceProfileActive()) {
                access_token_url += "&code_verifier=" + PkceUtil.codeVerifier;
            }

            response = restTemplate.exchange(access_token_url, HttpMethod.POST, request, String.class);

            System.out.println("Access Token Response ---------" + response.getBody());

            // Get the Access Token From the recieved JSON response
            ObjectMapper mapper = new ObjectMapper();
            JsonNode node = mapper.readTree(response.getBody());
            String token = node.path("access_token").asText();
            String refreshToken = node.path("refresh_token").asText();

            httpServletRequest.getSession().setAttribute("access_token", token);
            httpServletRequest.getSession().setAttribute("refresh_token", refreshToken);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void getTokenUsingRefreshToken(String refreshToken) {
        try {
            System.out.println("\n\n\n\n\n\nTrying to get new tokens using refresh token");
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "refresh_token");
            body.add("refresh_token", refreshToken);
            body.add("client_id", clientId);
            body.add("code_verifier",PkceUtil.codeVerifier);


            HttpHeaders headers = new HttpHeaders();

            if (!isPkceProfileActive()) {
                String credentials = clientId + ":" + clientSecret;
                String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
                headers.add("Authorization", "Basic " + encodedCredentials);
            } else {
                System.out.println("\n\n\nthis is still not working, fix me!!");
            }

            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            String url = serverUri + "/oauth2/token";
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);

            HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(body, headers);
            //noinspection unchecked
            Map<String, Object> response1 = restTemplate.postForObject(builder.build().toUriString(),
                    httpEntity, Map.class);
            System.out.println("Refresh Token Response ---------" + response1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}