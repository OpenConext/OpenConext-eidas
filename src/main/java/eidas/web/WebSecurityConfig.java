package eidas.web;

import static java.util.Collections.singletonList;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.servlet.Filter;
import javax.xml.stream.XMLStreamException;

import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostSimpleSignEncoder;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.security.provider.BasicSecurityPolicy;
import org.opensaml.ws.security.provider.StaticSecurityPolicyResolver;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import eidas.saml.CustomMetadataGenerator;
import eidas.saml.DefaultMetadataDisplayFilter;
import eidas.saml.IdentityProviderAuthnFilter;
import eidas.saml.KeyNamedJKSKeyManager;
import eidas.saml.KeyStoreLocator;
import eidas.saml.ProxiedSAMLContextProviderLB;
import eidas.saml.ProxySAMLAuthenticationProvider;
import eidas.saml.ProxyURIComparator;
import eidas.saml.ResourceMetadataProvider;
import eidas.saml.SAMLMessageHandler;
import eidas.saml.ServiceProvider;
import eidas.saml.ServiceProviderFeedParser;
import eu.stork.vidp.messages.common.STORKBootstrap;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private Environment environment;

  @Value("${proxy.base_url}")
  private String proxyBaseUrl;

  @Value("${proxy.entity_id}")
  private String proxyEntityId;

  @Value("${proxy.private_key}")
  private String proxyPrivateKey;

  @Value("${proxy.certificate}")
  private String proxyCertificate;

  @Value("${proxy.passphrase}")
  private String proxyPassphrase;

  @Value("${proxy.acs_location}")
  private String eidasACSLocation;

  @Value("${serviceproviders.feed}")
  private String serviceProvidersFeedUrl;

  @Value("${serviceproviders.allow_unknown}")
  private boolean serviceProvidersAllowUnknown;

  @Value("${server.port}")
  private int serverPort;

  @Value("${proxy.key_name}")
  private String proxyKeyName;

  @Value("${proxy.metadata_resource_sp}")
  private Resource metadataResourceSp;

  @Value("${sp.destination}")
  private String eidasDestination;

  @Value("${sp.certificate}")
  private String eidasCertificate;

  private DefaultResourceLoader defaultResourceLoader = new DefaultResourceLoader();

  private Map<String, ServiceProvider> serviceProviders;

  @PostConstruct
  public void init() throws ConfigurationException {
      STORKBootstrap.bootstrap();
  }

  @Bean
  public SAMLAuthenticationProvider samlAuthenticationProvider() {
    SAMLAuthenticationProvider samlAuthenticationProvider = new ProxySAMLAuthenticationProvider();
    samlAuthenticationProvider.setForcePrincipalAsString(false);
    samlAuthenticationProvider.setExcludeCredential(false);
    return samlAuthenticationProvider;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring().antMatchers("/health", "/info", "/service/catalog");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .httpBasic().authenticationEntryPoint(identityProviderAuthnFilter())
      .and()
      .csrf().disable()
      .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
      .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
      .authorizeRequests()
      .antMatchers("/saml/idp/**", "/sp/metadata", "/saml/acs/**", "/idp/metadata").permitAll()
      .anyRequest().hasRole("USER");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(samlAuthenticationProvider());
  }

  @Bean
  public MetadataDisplayFilter metadataDisplayFilter() {
    DefaultMetadataDisplayFilter displayFilter = new DefaultMetadataDisplayFilter();
    displayFilter.setFilterProcessesUrl("sp/metadata");
    return displayFilter;
  }

  @Bean
  public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
    SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    failureHandler.setUseForward(true);
    failureHandler.setDefaultFailureUrl("/error");
    return failureHandler;
  }

  @Bean
  @Autowired
  public MetadataGeneratorFilter metadataGeneratorFilter() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
    return new MetadataGeneratorFilter(metadataGenerator());
  }

  @Bean
  public FilterChainProxy samlFilter() throws Exception {
    List<SecurityFilterChain> chains = new ArrayList<>();
    chains.add(chain("/saml/idp/**", identityProviderAuthnFilter()));
    chains.add(chain("/sp/metadata/**", metadataDisplayFilter()));
    return new FilterChainProxy(chains);
  }

  @Bean
  public IdentityProviderAuthnFilter identityProviderAuthnFilter() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    return new IdentityProviderAuthnFilter(samlMessageHandler(), serviceProviders, serviceProvidersAllowUnknown, environment);
  }

  private DefaultSecurityFilterChain chain(String pattern, Filter entryPoint) {
    return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), entryPoint);
  }

  @Bean
  public ExtendedMetadata extendedMetadata() {
    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    extendedMetadata.setIdpDiscoveryEnabled(false);
    extendedMetadata.setSignMetadata(true);
    extendedMetadata.setTlsKey(proxyEntityId);
    extendedMetadata.setSigningAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    return extendedMetadata;
  }

  @Bean
  @Qualifier("metadata")
  public CachingMetadataManager metadata() throws MetadataProviderException {
    CachingMetadataManager metadataManager = new CachingMetadataManager(new ArrayList<>());
    metadataManager.setRefreshCheckInterval(1000 * 60 * 60);
    return metadataManager;
  }

  @Bean
  public VelocityEngine velocityEngine() {
    return VelocityFactory.getEngine();
  }

  @Bean(initMethod = "initialize")
  public ParserPool parserPool() {
    return new StaticBasicParserPool();
  }

  @Bean(name = "parserPoolHolder")
  public ParserPoolHolder parserPoolHolder() {
    return new ParserPoolHolder();
  }

  @Bean
  public SAMLContextProviderImpl contextProvider() throws URISyntaxException {
    return new ProxiedSAMLContextProviderLB(new URI(proxyBaseUrl));
  }

  @Bean
  public MetadataGenerator metadataGenerator() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    ResourceMetadataProvider resourceMetadataProvider = new ResourceMetadataProvider(this.metadataResourceSp);
    resourceMetadataProvider.setParserPool(parserPool());

    MetadataGenerator metadataGenerator = new CustomMetadataGenerator(resourceMetadataProvider);
    metadataGenerator.setExtendedMetadata(extendedMetadata());
    metadataGenerator.setIncludeDiscoveryExtension(false);
    metadataGenerator.setKeyManager(keyManager());
    if (environment.acceptsProfiles("dev")) {
      metadataGenerator.setWantAssertionSigned(false);
    }
    return metadataGenerator;
  }

  @Bean
  public KeyManager keyManager() throws InvalidKeySpecException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, XMLStreamException {
    KeyStoreLocator keyStoreLocator = new KeyStoreLocator();
    KeyStore keyStore = keyStoreLocator.createKeyStore(proxyPassphrase);

    keyStoreLocator.addPrivateKey(keyStore, proxyEntityId, proxyPrivateKey, proxyCertificate, proxyPassphrase);

    keyStoreLocator.addCertificate(keyStore, eidasDestination, eidasCertificate);

    this.serviceProviders = getServiceProviders();
    serviceProviders.entrySet().forEach(sp -> {
      try {
        ServiceProvider serviceProvider = sp.getValue();
        if (serviceProvider.isSigningCertificateSigned() && !serviceProvider.getEntityId().equals(proxyEntityId)) {
          keyStoreLocator.addCertificate(keyStore, sp.getKey(), serviceProvider.getSigningCertificate());
        }
      } catch (CertificateException | KeyStoreException e) {
        throw new RuntimeException(e);
      }
    });
    return new KeyNamedJKSKeyManager(keyStore, Collections.singletonMap(proxyEntityId, proxyPassphrase), proxyEntityId, proxyKeyName);
  }

  private Map<String, ServiceProvider> getServiceProviders() throws IOException, XMLStreamException {
    //expensive and we don't want the serviceProviders as @Bean
    if (this.serviceProviders == null) {
      this.serviceProviders = new ServiceProviderFeedParser(defaultResourceLoader.getResource(serviceProvidersFeedUrl)).parse();
    }
    if (environment.acceptsProfiles("dev")) {
      this.serviceProviders.put(proxyEntityId, new ServiceProvider(proxyEntityId, proxyCertificate, singletonList(eidasACSLocation)));
    }
    return this.serviceProviders;
  }

  @Bean
  public SAMLMessageHandler samlMessageHandler() throws NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, KeyStoreException, IOException, XMLStreamException {
    HTTPRedirectDeflateDecoder samlMessageDecoder = new HTTPRedirectDeflateDecoder(parserPool());
    samlMessageDecoder.setURIComparator(new ProxyURIComparator(this.proxyBaseUrl, "http://localhost:" + this.serverPort));
    return new SAMLMessageHandler(
      keyManager(),
      samlMessageDecoder,
      new HTTPPostSimpleSignEncoder(velocityEngine(), "/templates/saml2-post-simplesign-binding.vm", true),
      securityPolicyResolver(),
      proxyEntityId);
  }

  private SecurityPolicyResolver securityPolicyResolver() {
    IssueInstantRule instantRule = new IssueInstantRule(90, 300);
    MessageReplayRule replayRule = new MessageReplayRule(new ReplayCache(new MapBasedStorageService<>(), 14400000));

    BasicSecurityPolicy securityPolicy = new BasicSecurityPolicy();
    securityPolicy.getPolicyRules().addAll(Arrays.asList(instantRule, replayRule));

    return new StaticSecurityPolicyResolver(securityPolicy);
  }


}
