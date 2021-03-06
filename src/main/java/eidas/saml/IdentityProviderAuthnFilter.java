package eidas.saml;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.core.env.Environment;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;


public class IdentityProviderAuthnFilter extends OncePerRequestFilter implements AuthenticationEntryPoint {

  private final SAMLMessageHandler samlMessageHandler;
  private final Map<String, ServiceProvider> serviceProviders;
  private final boolean serviceProvidersAllowUnknown;
  private final Environment environment;

  public IdentityProviderAuthnFilter(SAMLMessageHandler samlMessageHandler,
                                     Map<String, ServiceProvider> serviceProviders,
                                     boolean serviceProvidersAllowUnknown,
                                     Environment environment) {
    this.samlMessageHandler = samlMessageHandler;
    this.serviceProviders = serviceProviders;
    this.serviceProvidersAllowUnknown = serviceProvidersAllowUnknown;
    this.environment = environment;
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    if (!isSAML(request)) {
      throw new IllegalArgumentException("No SAMLRequest or SAMLResponse query path parameter, invalid SAML 2 HTTP Redirect message");
    }

    //The SAMLRequest parameters are urlEncoded in local modus and the extraction expects unencoded parameters
    HttpServletRequest inputRequest = environment.acceptsProfiles("local") ?
      new ParameterDecodingHttpServletRequestWrapper(request) : request;

    SAMLMessageContext<?, ?, ?> messageContext = samlMessageHandler.extractSAMLMessageContext(inputRequest);

    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    SAMLPrincipal principal = new SAMLPrincipal(authnRequest.getIssuer().getValue(), authnRequest.getID(),
      authnRequest.getAssertionConsumerServiceURL(), messageContext.getRelayState());

    validateAssertionConsumerService(principal);

    SecurityContextHolder.getContext().setAuthentication(new SAMLAuthentication(principal));

    //forward to login page will trigger the sending of AuthRequest to the IdP
    request.getRequestDispatcher("/saml/login").forward(request, response);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    throws ServletException, IOException {
    if (!SAMLUtil.processFilter("/saml/idp", request)) {
      chain.doFilter(request, response);
      return;
    }
    commence(request, response, null);
  }

  private void validateAssertionConsumerService(SAMLPrincipal principal) {
    ServiceProvider serviceProvider = serviceProviders.get(principal.getServiceProviderEntityID());
    if (serviceProvider == null) {
      if (serviceProvidersAllowUnknown) {
        logger.warn("Allowing SP " + principal.getServiceProviderEntityID() + " because configured to allow unknown SPs");
        return;
      }
      throw new SAMLAuthenticationException("ServiceProvider " + principal.getServiceProviderEntityID() + " is unknown",
        null, principal);
    }
    if (!serviceProvider.getAssertionConsumerServiceURLs().contains(principal.getAssertionConsumerServiceURL())) {
      throw new SAMLAuthenticationException("ServiceProvider " + principal.getServiceProviderEntityID() + " has not published ACS "
        + principal.getAssertionConsumerServiceURL() + " in their assertionConsumerURLS: " + serviceProvider.getAssertionConsumerServiceURLs(),
        null, principal);
    }
  }

  private boolean isSAML(HttpServletRequest request) {
    return StringUtils.hasText(request.getParameter("SAMLResponse"))
      || StringUtils.hasText(request.getParameter("SAMLRequest"));

  }
}
