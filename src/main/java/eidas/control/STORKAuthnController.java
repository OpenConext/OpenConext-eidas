package eidas.control;

import static org.apache.commons.io.Charsets.UTF_8;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.Charsets;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import eidas.saml.STORKAuthnService;
import eu.stork.mw.messages.saml.STORKAuthnRequest;
import eu.stork.mw.messages.saml.STORKResponse;
import eu.stork.vidp.messages.exception.SAMLException;
import eu.stork.vidp.messages.util.XMLUtil;

@Controller
public class STORKAuthnController {

    private static final Logger LOGGER = LoggerFactory.getLogger(STORKAuthnController.class);

    @Autowired
    private STORKAuthnService authnService;

    @RequestMapping(value = "/saml/login", method = RequestMethod.GET)
    public ModelAndView samlLogin() throws Exception {
        Map<String, String> m = new LinkedHashMap<>();
        STORKAuthnRequest storkAuthnRequest = authnService.buildSTORKAuthnRequest();
        String requestStr = new String(Base64.getEncoder().encode(XMLUtil.printXML(storkAuthnRequest.getDOM()).getBytes(UTF_8)), UTF_8);
        m.put("requestStr", requestStr);
        m.put("countrycode", "BE");
        m.put("pepsUrl", storkAuthnRequest.getDestination());
        return new ModelAndView("storkRequest", "model", m);
    }

    @RequestMapping(value = "/saml/acs", method = RequestMethod.POST)
    public ModelAndView samlAssertionConsumerService(@RequestParam(required = true, value = "SAMLResponse") String samlResponse) throws SAMLException {

        byte[] response = Base64.getDecoder().decode(samlResponse);
        String samlResponseXML = new String(response, UTF_8);
        STORKResponse storkResponse = authnService.buildSTORKResponse(samlResponseXML);

        LOGGER.info("Received SAMLResponse: " + XMLUtil.printXML(storkResponse.getDOM()));

        List<Assertion> assertions = storkResponse.getAssertions();
        if (storkResponse.getStatus().getStatusCode().getValue().endsWith(StatusCode.SUCCESS.getLocalPart())) {
            List<Attribute> attributes = new ArrayList<>();
            for (Assertion assertion : assertions) {
                List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
                for (AttributeStatement attributeStatement : attributeStatements) {
                    attributes.addAll(attributeStatement.getAttributes());
                }
            }
            return new ModelAndView("response", "attributes", attributes);
        } else {
            return new ModelAndView("response", "errorMessage", storkResponse.getStatus().getStatusMessage().getMessage());
        }
    }
}
