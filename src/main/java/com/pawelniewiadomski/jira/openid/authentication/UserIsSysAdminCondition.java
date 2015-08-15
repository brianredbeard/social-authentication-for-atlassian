package com.pawelniewiadomski.jira.openid.authentication;

import com.atlassian.plugin.PluginParseException;
import com.atlassian.plugin.web.Condition;
import com.atlassian.sal.api.user.UserManager;

import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

public class UserIsSysAdminCondition implements Condition {
    final UserManager userManager;

    public UserIsSysAdminCondition(UserManager userManager) {
        this.userManager = checkNotNull(userManager);
    }

    @Override
    public void init(Map<String, String> map) throws PluginParseException {
    }

    @Override
    public boolean shouldDisplay(Map<String, Object> map) {
        final String user = userManager.getRemoteUsername();
        return user != null && userManager.isSystemAdmin(user);
    }
}
