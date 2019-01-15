package com.pawelniewiadomski.jira.openid.authentication.providers;

import com.atlassian.fugue.Either;
import com.atlassian.fugue.Pair;
import com.atlassian.sal.api.message.I18nResolver;
import com.google.common.collect.ImmutableList;
import com.pawelniewiadomski.jira.openid.authentication.ReturnToHelper;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdDao;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdProvider;
import com.pawelniewiadomski.jira.openid.authentication.openid.OpenIdConnectResponse;
import org.apache.log4j.Logger;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.OAuthProviderType;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.defaultIfEmpty;
import static org.apache.commons.lang.StringUtils.defaultString;

public class GoogleProviderType extends AbstractOAuth2ProviderType {

    public static final String SELECT_ACCOUNT_PROMPT = DiscoverablyOauth2ProviderType.SELECT_ACCOUNT_PROMPT;

    final Logger log = Logger.getLogger(this.getClass());
    private final ReturnToHelper returnToHelper;

    public GoogleProviderType(I18nResolver i18nResolver, OpenIdDao openIdDao, ReturnToHelper returnToHelper) {
        super(i18nResolver, openIdDao);
        this.returnToHelper = returnToHelper;
    }

    @Nonnull
    @Override
    public String getId() {
        return OpenIdProvider.GOOGLE_TYPE;
    }

    @Nonnull
    @Override
    public String getName() {
        return i18nResolver.getText("openid.provider.type.google");
    }

    @Nonnull
    @Override
    public String getAuthorizationUrl() {
        return OAuthProviderType.GOOGLE.getAuthzEndpoint();
    }

    @Nonnull
    @Override
    public String getCallbackId() {
        return "google";
    }

    @Nullable
    @Override
    public String getDefaultName() {
        return "Google";
    }

    @Override
    public List<String> getSupportedPrompts() {
        return ImmutableList.of("login", SELECT_ACCOUNT_PROMPT);
    }

    @Override
    public OAuthClientRequest createOAuthRequest(@Nonnull OpenIdProvider provider,
                                                 @Nonnull String state,
                                                 @Nonnull HttpServletRequest request) throws Exception {
        return OAuthClientRequest
                .authorizationLocation(OAuthProviderType.GOOGLE.getAuthzEndpoint())
                .setClientId(provider.getClientId())
                .setResponseType(ResponseType.CODE.toString())
                .setState(state)
                .setScope("openid email profile")
                .setParameter("prompt", defaultString(provider.getPrompt(), SELECT_ACCOUNT_PROMPT))
                .setRedirectURI(returnToHelper.getReturnTo(provider, request))
                .buildQueryMessage();
    }

    @Override
    public Either<Pair<String, String>, Error> getUsernameAndEmail(@Nonnull String authorizationCode, @Nonnull OpenIdProvider provider, @Nonnull HttpServletRequest request) throws Exception {
        final OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        final OAuthClientRequest oAuthRequest = OAuthClientRequest.tokenLocation("https://www.googleapis.com/oauth2/v4/token")
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setClientId(provider.getClientId())
                .setClientSecret(provider.getClientSecret())
                .setRedirectURI(returnToHelper.getReturnTo(provider, request))
                .setCode(authorizationCode)
                .buildBodyMessage();

        final OpenIdConnectResponse token = oAuthClient.accessToken(oAuthRequest, OpenIdConnectResponse.class);
        final String accessToken = token.getAccessToken();
        //noinspection ConstantConditions
        final String email = token.getIdToken().get().getClaimsSet().getCustomField("email", String.class);

        final OAuthClientRequest bearerClientRequest = new OAuthBearerClientRequest("https://openidconnect.googleapis.com/v1/userinfo")
                .setAccessToken(accessToken)
                .buildHeaderMessage();

        try {
            final OAuthResourceResponse userInfoResponse = oAuthClient.resource(bearerClientRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
            final Map<String, Object> userInfo = JSONUtils.parseJSON(userInfoResponse.getBody());
            final String username = defaultIfEmpty((String) userInfo.get("name"), email);

            return Either.left(Pair.pair(username, email));
        } catch(OAuthSystemException e) {
            if (e.getMessage().contains("https://www.googleapis.com/plus/v1/people/me/openIdConnect")) {
                log.error("OpenID verification failed", e);
                return Either.right(Error.builder().errorMessage(i18nResolver.getText("google.plus.api.error")).build());
            } else {
                throw e;
            }
        }
    }
}
