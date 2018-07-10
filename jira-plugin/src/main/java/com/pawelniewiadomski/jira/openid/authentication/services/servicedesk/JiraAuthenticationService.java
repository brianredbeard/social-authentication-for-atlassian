package com.pawelniewiadomski.jira.openid.authentication.services.servicedesk;

import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.exception.InvalidUserException;
import com.atlassian.crowd.exception.UserAlreadyExistsException;
import com.atlassian.crowd.search.query.entity.UserQuery;
import com.atlassian.crowd.search.query.entity.restriction.MatchMode;
import com.atlassian.crowd.search.query.entity.restriction.TermRestriction;
import com.atlassian.crowd.search.query.entity.restriction.constants.UserTermKeys;
import com.atlassian.jira.bc.user.UserService;
import com.atlassian.jira.exception.CreateException;
import com.atlassian.jira.security.login.LoginManager;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.jira.user.ApplicationUsers;
import com.atlassian.jira.user.UserDetails;
import com.atlassian.jira.user.util.UserManager;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.service.rememberme.RememberMeService;
import com.google.common.collect.Iterables;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdProvider;
import com.pawelniewiadomski.jira.openid.authentication.services.AuthenticationService;
import com.pawelniewiadomski.jira.openid.authentication.services.ExternalUserManagementService;
import com.pawelniewiadomski.jira.openid.authentication.services.GlobalSettings;
import com.pawelniewiadomski.jira.openid.authentication.services.ProvidedUserDetails;
import com.pawelniewiadomski.jira.openid.authentication.services.RedirectionService;
import com.pawelniewiadomski.jira.openid.authentication.services.TemplateHelper;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.atlassian.jira.component.ComponentAccessor.getComponentOfType;
import static com.pawelniewiadomski.AllowedDomains.isEmailFromAllowedDomain;
import static java.util.UUID.randomUUID;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.apache.commons.lang.StringUtils.lowerCase;
import static org.apache.commons.lang.StringUtils.replaceChars;
import static org.apache.commons.lang.StringUtils.stripToEmpty;

@Slf4j
@Component
public class JiraAuthenticationService implements AuthenticationService {
    @Autowired
    protected UserService userService;

    @Autowired
    protected CrowdService crowdService;

    @Autowired
    protected GlobalSettings globalSettings;

    @Autowired
    protected TemplateHelper templateHelper;

    @Autowired
    protected ExternalUserManagementService externalUserManagementService;

    @Autowired
    protected RedirectionService redirectionService;

    public void showAuthentication(final HttpServletRequest request, final HttpServletResponse response,
                                   final OpenIdProvider provider, final ProvidedUserDetails userDetails) throws IOException, ServletException {
        if (isBlank(userDetails.getEmail())) {
            templateHelper.render(request, response, "OpenId.Templates.emptyEmail");
            return;
        }

        if (isNotBlank(provider.getAllowedDomains())) {
            if (!isEmailFromAllowedDomain(provider, userDetails.getEmail())) {
                templateHelper.render(request, response, "OpenId.Templates.domainMismatch");
                return;
            }
        }

        ApplicationUser user = getUserByEmail(userDetails);
        if (user == null && !externalUserManagementService.isExternalUserManagement() && globalSettings.isCreatingUsers()) {
            try {
                final String userName = lowerCase(replaceChars(userDetails.getIdentity(), " '()", ""));

                for (int i = 0; i < 10 && user == null; ++i) {
                    try {
                        val tryUserName = userName + (i == 0 ? "" : i);

                        UserService.CreateUserRequest createUserRequest = UserService.CreateUserRequest.withUserDetails(
                                null,
                                tryUserName,
                                randomUUID().toString(),
                                userDetails.getEmail(),
                                userDetails.getIdentity())
                                .sendNotification(false)
                                .skipValidation();

                        user = userService.createUser(userService.validateCreateUser(createUserRequest));
                    } catch (CreateException e) {
                        if (!(e.getCause() instanceof UserAlreadyExistsException || e.getCause() instanceof InvalidUserException)) {
                            throw e;
                        }
                    }
                }
            } catch (Exception e) {
                log.error(String.format("Cannot create an account for %s %s", userDetails.getIdentity(), userDetails.getEmail()), e);
                templateHelper.render(request, response, "OpenId.Templates.error");
                return;
            }
        }

        if (user != null) {
            final HttpSession httpSession = request.getSession();
            httpSession.setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
            httpSession.setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
            getComponentOfType(LoginManager.class).onLoginAttempt(request, user.getName(), true);

            getComponentOfType(RememberMeService.class).addRememberMeCookie(request, response, user.getUsername());

            redirectionService.redirectToReturnUrlOrHome(request, response);
        } else {
            templateHelper.render(request, response, "OpenId.Templates.noUserMatched");
        }
    }

    private ApplicationUser getUserByEmail(ProvidedUserDetails userDetails) {
        return ApplicationUsers.from((User) Iterables.getFirst(crowdService.search(new UserQuery(
                User.class, new TermRestriction(UserTermKeys.EMAIL, MatchMode.EXACTLY_MATCHES,
                stripToEmpty(userDetails.getEmail()).toLowerCase()), 0, 1)), null));
    }
}
