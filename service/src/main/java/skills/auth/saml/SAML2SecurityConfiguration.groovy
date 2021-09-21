/**
 * Copyright 2020 SkillTree
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package skills.auth.saml

import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.*
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations
import org.springframework.stereotype.Component
import skills.auth.PortalWebSecurityHelper
import skills.auth.SecurityMode

@Slf4j
@Conditional(SecurityMode.SAML2Auth)
@Component
@Configuration
/** Supports Single Identity Provider Only **/
class SAML2SecurityConfiguration extends WebSecurityConfigurerAdapter {

    public static final String SKILLS_REDIRECT_URI = 'skillsRedirectUri'

    @Value('${spring.security.saml2.metadata-location}')
    String assertingPartyMetadataLocation;

    @Value('${spring.security.saml2.registrationId}')
    String registrationId;

    @Autowired
    PortalWebSecurityHelper portalWebSecurityHelper

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        portalWebSecurityHelper.configureHttpSecurity(http).securityContext().securityContextRepository(httpSessionSecurityContextRepository());
        http.saml2Login();
        http.logout().logoutSuccessUrl("/saml2/logout")
    }

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration registration = RelyingPartyRegistrations.fromMetadataLocation(assertingPartyMetadataLocation)
                .registrationId(registrationId)
                .build()
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    @Bean
    UserDetailsService userDetailsService(){
        return super.userDetailsService();
    }

    @Override
    @Bean(name = 'defaultAuthManager')
    @Primary
    @Lazy
    AuthenticationManager authenticationManagerBean() throws Exception {
        // provides the default AuthenticationManager as a Bean
        return super.authenticationManagerBean()
    }

    @Bean
    Saml2HttpSessionSecurityContextRepository httpSessionSecurityContextRepository() {
        return new Saml2HttpSessionSecurityContextRepository()
    }


}