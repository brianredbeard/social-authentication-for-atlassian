package com.pawelniewiadomski.jira.openid.authentication.openid;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.reflect.MethodUtils;
import org.apache.oltu.oauth2.client.response.GitHubTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.token.OAuthToken;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.oltu.oauth2.jwt.JWT;
import org.apache.oltu.oauth2.jwt.io.JWTReader;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;

import static java.lang.String.format;

@Slf4j
public class OpenIdConnectResponse extends OAuthAccessTokenResponse {
    private OAuthAccessTokenResponse response;

    @Override
    public String getAccessToken() {
        return response.getAccessToken();
    }

    @Override
    public String getTokenType() {
        return response.getTokenType();
    }

    @Override
    public Long getExpiresIn() {
        return response.getExpiresIn();
    }

    @Override
    public String getRefreshToken() {
        return response.getRefreshToken();
    }

    @Override
    public String getScope() {
        return response.getScope();
    }

    @Override
    public OAuthToken getOAuthToken() {
        return response.getOAuthToken();
    }

    @Override
    protected void setContentType(String contentType) {
        throw new NotImplementedException("setContentType should not be called");
    }

    @Override
    protected void setResponseCode(int responseCode) {
        throw new NotImplementedException("setResponseCode should not be called");
    }

    @Override
    protected void init(String body, String contentType, int responseCode)
            throws OAuthProblemException {
        log.info(format("Response content type %s with code %d and body %s", contentType, responseCode, body));

        if (OAuthUtils.isFormEncoded(contentType)) {
            this.response = new GitHubTokenResponse();
        } else {
            this.response = new OAuthJSONAccessTokenResponse();
        }

        try {
            val initMethod = getMethod(this.response.getClass(),"init", String.class, String.class, int.class);
            initMethod.setAccessible(true);
            initMethod.invoke(this.response, body, contentType, responseCode);
        } catch (IllegalAccessException | InvocationTargetException e) {
            log.error("cannot call init method", e);
            throw new IllegalStateException("cannot call init method", e);
        }
    }

    public final Optional<JWT> getIdToken() {
        return Optional.ofNullable(getParam("id_token")).map((idToken) -> new JWTReader().read(idToken));
    }

    public static Method getMethod(Class<?> instanceClass, String name, Class<?>... parameterTypes) {
        if(ObjectUtils.notEqual(instanceClass,null) && StringUtils.isNotEmpty(name)) {
            Class<?> searchType = instanceClass;

            while (searchType != null) {
                Method[] methods = (searchType.isInterface() ? searchType.getMethods() : searchType.getDeclaredMethods());

                for (Method method : methods) {
                    if (name.equals(method.getName()) && (parameterTypes == null || Arrays.equals(parameterTypes, method.getParameterTypes()))) {
                        return method;
                    }
                }

                searchType = searchType.getSuperclass();
            }
        }

        return null;
    }
}
