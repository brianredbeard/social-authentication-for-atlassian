package com.pawelniewiadomski.servicedesk.services;

import com.pawelniewiadomski.jira.openid.authentication.services.HomePageService;
import org.springframework.stereotype.Component;

@Component
public class ServiceDeskHomePageService implements HomePageService {
    @Override
    public String getHomePagePath() {
        return "/secure/Dashboard.jspa";
    }
}
