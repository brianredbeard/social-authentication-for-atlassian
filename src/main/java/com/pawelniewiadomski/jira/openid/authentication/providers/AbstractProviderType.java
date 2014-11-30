package com.pawelniewiadomski.jira.openid.authentication.providers;

import com.atlassian.sal.api.message.I18nResolver;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdDao;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdProvider;
import com.pawelniewiadomski.jira.openid.authentication.rest.responses.ProviderBean;

import javax.annotation.Nullable;
import java.sql.SQLException;

import static org.apache.commons.lang3.StringUtils.isEmpty;

public abstract class AbstractProviderType implements ProviderType {

    protected final I18nResolver i18nResolver;
    protected final OpenIdDao openIdDao;

    public AbstractProviderType(I18nResolver i18nResolver, OpenIdDao openIdDao) {
        this.i18nResolver = i18nResolver;
        this.openIdDao = openIdDao;
    }

    protected void validateName(OpenIdProvider provider, ProviderBean providerBean, com.atlassian.jira.util.ErrorCollection errors) {
        if (isEmpty(providerBean.getName())) {
            errors.addError("name", i18nResolver.getText("configuration.name.empty"));
        } else {
            final OpenIdProvider providerByName;
            try {
                providerByName = openIdDao.findByName(providerBean.getName());
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }

            if (providerByName != null && (provider == null || providerByName.getID() != provider.getID())) {
                errors.addError("name", i18nResolver.getText("configuration.name.must.be.unique"));
            }
        }
    }

    @Override
    public boolean isSkipClientInfo() {
        return false;
    }

    @Override
    public boolean isSkipCallback() {
        return false;
    }

    @Override
    public boolean isSkipUrl() {
        return false;
    }

    @Nullable
    @Override
    public String getCreatedProviderName() {
        return null;
    }
}
