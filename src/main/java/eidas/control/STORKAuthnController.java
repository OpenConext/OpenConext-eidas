package eidas.control;

import static java.util.stream.Collectors.toList;
import static org.apache.commons.io.Charsets.UTF_8;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.NameID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import eidas.saml.SAMLAttribute;
import eidas.saml.SAMLBuilder;
import eidas.saml.SAMLMessageHandler;
import eidas.saml.SAMLPrincipal;
import eidas.saml.STORKAuthnService;
import eu.stork.mw.messages.saml.STORKAuthnRequest;
import eu.stork.mw.messages.saml.STORKResponse;
import eu.stork.vidp.messages.exception.SAMLException;
import eu.stork.vidp.messages.util.XMLUtil;

@Controller
public class STORKAuthnController {

    private static final Logger LOGGER = LoggerFactory.getLogger(STORKAuthnController.class);

    private final STORKAuthnService authnService;

    private final SAMLMessageHandler samlMessageHandler;

    @Autowired
    public STORKAuthnController(STORKAuthnService authnService, SAMLMessageHandler samlMessageHandler) {
      this.authnService = authnService;
      this.samlMessageHandler = samlMessageHandler;
    }

    @RequestMapping(value = "/saml/login", method = RequestMethod.GET)
    public ModelAndView samlLogin() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        STORKAuthnRequest storkAuthnRequest = authnService.buildSTORKAuthnRequest();
        String requestStr = new String(Base64.getEncoder().encode(XMLUtil.printXML(storkAuthnRequest.getDOM()).getBytes(UTF_8)), UTF_8);
        m.put("requestStr", requestStr);
        m.put("countrycode", "DR");
        m.put("pepsUrl", storkAuthnRequest.getDestination());
        return new ModelAndView("storkRequest", "model", m);
    }

    @RequestMapping(value = "/saml/acs", method = RequestMethod.POST)
    public ModelAndView samlAssertionConsumerService(@RequestParam(required = true, value = "SAMLResponse") String samlResponse, HttpServletResponse servletResponse) throws SAMLException {
        byte[] response = Base64.getDecoder().decode(samlResponse);
        String samlResponseXML = new String(response, UTF_8);
        STORKResponse storkResponse = authnService.buildSTORKResponse(samlResponseXML);

        LOGGER.info("Received SAMLResponse: " + XMLUtil.printXML(storkResponse.getDOM()));

        List<Assertion> assertions = storkResponse.getAssertions();
        if (storkResponse.getStatus().getStatusCode().getValue().endsWith(StatusCode.SUCCESS.getLocalPart())) {
            List<SAMLAttribute> attributes = new ArrayList<>();
            for (Assertion assertion : assertions) {
                List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
                for (AttributeStatement attributeStatement : attributeStatements) {
                    for (Attribute attribute : attributeStatement.getAttributes()) {
                        attributes.add(new SAMLAttribute(
                            attribute.getName(),
                            attribute.getAttributeValues().stream().map(attributeValue ->
                                SAMLBuilder.getStringValueFromXMLObject(attributeValue)
                            ).filter(Optional::isPresent).map(Optional::get).collect(toList())
                        ));
                    }
                }
            }

            SAMLPrincipal principal = (SAMLPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            NameID nameID = storkResponse.getAssertions().get(0).getSubject().getNameID();
            principal.elevate(nameID.getValue(), nameID.getFormat(), attributes);
            samlMessageHandler.sendAuthnResponse(principal, servletResponse);
            return null;
        } else {
            return new ModelAndView("response", "errorMessage", storkResponse.getStatus().getStatusMessage().getMessage());
        }
    }
}
