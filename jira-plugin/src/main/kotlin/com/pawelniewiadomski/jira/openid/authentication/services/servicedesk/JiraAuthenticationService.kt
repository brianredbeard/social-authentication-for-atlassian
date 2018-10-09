package com.pawelniewiadomski.jira.openid.authentication.services.servicedesk

import com.atlassian.crowd.embedded.api.CrowdService
import com.atlassian.crowd.search.query.entity.UserQuery
import com.atlassian.crowd.search.query.entity.restriction.MatchMode
import com.atlassian.crowd.search.query.entity.restriction.TermRestriction
import com.atlassian.crowd.search.query.entity.restriction.constants.UserTermKeys
import com.atlassian.jira.compatibility.bridge.user.UserUtilBridge
import com.atlassian.jira.compatibility.factory.user.UserUtilBridgeFactory
import com.atlassian.jira.security.login.LoginManager
import com.atlassian.jira.user.ApplicationUsers
import com.atlassian.seraph.auth.DefaultAuthenticator
import com.atlassian.seraph.service.rememberme.RememberMeService
import com.google.common.collect.Iterables
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdProvider
import com.pawelniewiadomski.jira.openid.authentication.services.*
import com.pawelniewiadomski.AlloweDomains.Companion.isEmailFromAllowedDomain
import lombok.extern.slf4j.Slf4j
import org.apache.commons.lang.StringUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.io.IOException

import com.atlassian.jira.component.ComponentAccessor.getComponentOfType
import java.util.UUID.randomUUID
import org.apache.commons.lang.StringUtils.*

@Slf4j
@Component
class JiraAuthenticationService : AuthenticationService {
    @Autowired protected var userUtilBridgeFactory: UserUtilBridgeFactory? = null

    @Autowired protected var crowdService: CrowdService? = null

    @Autowired protected var globalSettings: GlobalSettings? = null

    @Autowired protected var templateHelper: TemplateHelper? = null

    @Autowired protected var externalUserManagementService: ExternalUserManagementService? = null

    @Autowired protected var redirectionService: RedirectionService? = null

    @Throws(IOException::class, ServletException::class)
    override fun showAuthentication(request: HttpServletRequest, response: HttpServletResponse,
                                    provider: OpenIdProvider, identity: String, email: String) {
        if (isBlank(email)) {
            templateHelper!!.render(request, response, "OpenId.Templates.emptyEmail")
            return
        }

        if (isNotBlank(provider.allowedDomains)) {
            if (!isEmailFromAllowedDomain(provider, email)) {
                templateHelper!!.render(request, response, "OpenId.Templates.domainMismatch")
                return
            }
        }

        var user = Iterables.getFirst(crowdService!!.search<Any>(UserQuery(
                com.atlassian.crowd.embedded.api.User::class.java!!, TermRestriction(UserTermKeys.EMAIL, MatchMode.EXACTLY_MATCHES,
                StringUtils.stripToEmpty(email).toLowerCase()), 0, 1)), null) as com.atlassian.crowd.embedded.api.User?

        if (user == null && !externalUserManagementService!!.isExternalUserManagement && globalSettings!!.isCreatingUsers) {
            try {
                val userUtil = userUtilBridgeFactory!!.`object` as UserUtilBridge
                user = ApplicationUsers.toDirectoryUser(userUtil.createUserNoNotification(lowerCase(replaceChars(identity, " '()", "")), randomUUID().toString(),
                        email, identity))
            } catch (e: Exception) {
                log.error(String.format("Cannot create an account for %s %s", identity, email), e)
                templateHelper!!.render(request, response, "OpenId.Templates.error")
                return
            }

        }

        if (user != null) {
            val appUser = ApplicationUsers.from(user)

            val httpSession = request.session
            httpSession.setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, appUser)
            httpSession.setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null)
            getComponentOfType<LoginManager>(LoginManager::class.java).onLoginAttempt(request, appUser!!.name, true)

            getComponentOfType<RememberMeService>(RememberMeService::class.java).addRememberMeCookie(request, response, appUser.username)

            redirectionService!!.redirectToReturnUrlOrHome(request, response)
        } else {
            templateHelper!!.render(request, response, "OpenId.Templates.noUserMatched")
        }
    }
}
