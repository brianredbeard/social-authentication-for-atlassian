package com.pawelniewiadomski.jira.openid.authentication.rest;

import com.atlassian.fugue.Either;
import com.google.common.base.Function;
import com.google.common.base.Supplier;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdDao;
import com.pawelniewiadomski.jira.openid.authentication.activeobjects.OpenIdProvider;
import com.pawelniewiadomski.jira.openid.authentication.providers.Errors;
import com.pawelniewiadomski.jira.openid.authentication.rest.responses.ProviderBean;
import com.pawelniewiadomski.jira.openid.authentication.services.ProviderValidator;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Path("providers")
@Produces({MediaType.APPLICATION_JSON})
public class ProvidersResource {
    @Autowired
    protected OpenIdDao openIdDao;

    @Autowired
    protected ProviderValidator validator;

    @Autowired
    protected OpenIdResource openIdResource;

    @POST
    public Response createProvider(final ProviderBean providerBean) {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(
                new Supplier<Response>() {
                    @Override
                    public Response get() {
                        Either<Errors, OpenIdProvider> errorsOrProvider = validator.validateAndCreate(providerBean);

                        if (errorsOrProvider.isLeft()) {
                            return Response.ok(errorsOrProvider.left().get()).build();
                        } else {
                            return Response.ok(ProviderBean.of(errorsOrProvider.right().get())).build();
                        }
                    }
                }
        );
    }

    @PUT
    @Path("/{providerId}")
    public Response updateProvider(@PathParam("providerId") final int providerId, final ProviderBean providerBean) {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(
                new Supplier<Response>() {
                    @Override
                    public Response get() {
                        try {
                            final OpenIdProvider provider = openIdDao.findProvider(providerId);
                            final Either<Errors, OpenIdProvider> errorsOrProvider = validator.validateAndUpdate(provider, providerBean);

                            if (errorsOrProvider.isLeft()) {
                                return Response.ok(errorsOrProvider.left().get()).build();
                            } else {
                                return Response.ok(ProviderBean.of(errorsOrProvider.right().get())).build();
                            }
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
        );
    }

    @DELETE
    @Path("/{providerId}")
    public Response deleteProvider(@PathParam("providerId") final int providerId) {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(new Supplier<Response>() {
            @Override
            public Response get() {
                try {
                    openIdDao.deleteProvider(providerId);
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
                return Response.noContent().build();
            }
        });
    }

    @POST
    @Path("/moveUp/{providerId}")
    public Response moveProviderUp(@PathParam("providerId") final int providerId) {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(new Supplier<Response>() {
            @Override
            public Response get() {
                try {
                    final List<OpenIdProvider> providers = openIdDao.findAllProviders();
                    if (providers.size() > 1 && providerId != providers.get(0).getID()) {
                        for (int i = 1, s = providers.size(); i < s; ++i) {
                            final OpenIdProvider currentProvider = providers.get(i);
                            if (currentProvider.getID() == providerId) {
                                final OpenIdProvider previousProvider = providers.get(i - 1);
                                final int order = currentProvider.getOrdering();

                                currentProvider.setOrdering(previousProvider.getOrdering());
                                previousProvider.setOrdering(order);

                                currentProvider.save();
                                previousProvider.save();
                                break;
                            }
                        }
                    }
                } catch (SQLException e) {
                    log.warn("Unable to modify Providers", e);
                }

                return ProvidersResource.this.getProvidersResponse();
            }
        });
    }

    @POST
    @Path("/moveDown/{providerId}")
    public Response moveProviderDown(@PathParam("providerId") final int providerId) {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(new Supplier<Response>() {
            @Override
            public Response get() {
                try {
                    final List<OpenIdProvider> providers = openIdDao.findAllProviders();
                    if (providers.size() > 1 && providerId != providers.get(providers.size() - 1).getID()) {
                        for (int i = 0, s = providers.size() - 1; i < s; ++i) {
                            final OpenIdProvider currentProvider = providers.get(i);
                            if (currentProvider.getID() == providerId) {
                                final OpenIdProvider nextProvider = providers.get(i + 1);
                                final int order = currentProvider.getOrdering();

                                currentProvider.setOrdering(nextProvider.getOrdering());
                                nextProvider.setOrdering(order);

                                currentProvider.save();
                                nextProvider.save();
                                break;
                            }
                        }
                    }
                } catch (SQLException e) {
                    log.warn("Unable to modify Providers", e);
                }
                return ProvidersResource.this.getProvidersResponse();
            }
        });
    }

    @POST
    @Path("/{providerId}/state")
    public Response setState(@PathParam("providerId") final int providerId, final Map<String, Boolean> params) {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(new Supplier<Response>() {
            @Override
            public Response get() {
                try {
                    OpenIdProvider provider = openIdDao.findProvider(providerId);
                    if (provider != null) {
                        provider.setEnabled(params.get("enabled"));
                        provider.save();
                    }
                } catch (SQLException e) {
                    log.warn("Unable to modify Providers", e);
                }
                return ProvidersResource.this.getProvidersResponse();
            }
        });
    }

    protected Response getProvidersResponse() {
        try {
            return Response.ok(Lists.newArrayList(
                    openIdDao.findAllProviders().stream().map(ProviderBean::of).collect(Collectors.toList())))
                    .cacheControl(openIdResource.never()).build();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @GET
    public Response getOpenIdProviders() {
        return openIdResource.permissionDeniedIfNotAdmin().getOrElse(new Supplier<Response>() {
            @Override
            public Response get() {
                return ProvidersResource.this.getProvidersResponse();
            }
        });
    }
}
