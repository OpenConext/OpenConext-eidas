package eidas.saml;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import eu.stork.mw.messages.saml.STORKAuthnRequest;
import eu.stork.mw.messages.saml.STORKResponse;
import eu.stork.vidp.messages.builder.STORKMessagesBuilder;
import eu.stork.vidp.messages.common.STORKConstants;
import eu.stork.vidp.messages.exception.SAMLException;
import eu.stork.vidp.messages.exception.SAMLValidationException;
import eu.stork.vidp.messages.stork.QualityAuthenticationAssuranceLevel;
import eu.stork.vidp.messages.stork.RequestedAttributes;
import eu.stork.vidp.messages.util.SAMLUtil;
import eu.stork.vidp.messages.util.XMLUtil;

@Service
public class STORKAuthnService {

    private static final Logger LOGGER = LoggerFactory.getLogger(STORKAuthnService.class);

    @Value("${sp.destination}")
    private String destination;
    @Value("${sp.acs_url}")
    private String acsURL;
    @Value("${sp.provider_name}")
    private String providerName;
    @Value("${sp.issuer}")
    private String issuer;
    @Value("${sp.qaa_level}")
    private int qaa;
    @Value("${sp.sector}")
    private String spSector;
    @Value("${sp.institution}")
    private String spInstitution;
    @Value("${sp.application}")
    private String spApplication;
    @Value("${sp.country}")
    private String spCountry;

    @Value("${sp.requested_attributes.names}")
    private String[] requestedAttributeNames;
    @Value("${sp.requested_attributes.mandatory_values}")
    private String[] requestedAttributeMandatoryValues;
    @Value("${sp.requested_attributes.optional_values}")
    private String[] requestedAttributeOptionalValues;

    private KeyManager keyManager;

    @Autowired
    public STORKAuthnService(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public STORKAuthnRequest buildSTORKAuthnRequest() throws Exception {
        QualityAuthenticationAssuranceLevel qaaLevel = STORKMessagesBuilder.buildQualityAuthenticationAssuranceLevel(qaa);

        // List of STORK attributes to be requested
        List<RequestedAttribute> requestedAttributeList = getRequestedAttributes();
        RequestedAttributes requestedAttributes = STORKMessagesBuilder.buildRequestedAttributes(requestedAttributeList);

        return signSTORKAuthnRequest(STORKMessagesBuilder.buildSTORKAuthnRequest(
                destination,
                acsURL,
                providerName,
                issuer,
                qaaLevel,
                requestedAttributes,
                spSector,
                spInstitution,
                spApplication,
                spCountry));
    }

    public STORKResponse buildSTORKResponse(String samlResponse) throws SAMLException {
        STORKResponse response = null;
        Element el;
        try {
            el = XMLUtil.stringToDOM(samlResponse);
            Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(el);
            XMLObject message = unmarshaller.unmarshall(el);
            SAMLObject inboundMessage = (SAMLObject) message;
            response = (STORKResponse) inboundMessage;
            SAMLUtil.verifySAMLObjectStandardValidation(response, "saml2-core-schema-and-stork-validator");
            SAMLUtil.validateSignatureReferences(response);
            validateSignature(response);
        } catch (ParserConfigurationException | SAXException | IOException | UnmarshallingException | SAMLValidationException | ValidationException e) {
            LOGGER.error(e.getMessage(), e);
            throw new SAMLException(e);
        }
        return response;
    }

    private void validateSignature(STORKResponse response) throws ValidationException {
        Credential verificationCredential = keyManager.getCredential(destination);
        SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
        sigValidator.validate(response.getSignature());
        List<Assertion> assertions = response.getAssertions();
        if (assertions != null) {
            for (Assertion assertion : assertions) {
                sigValidator.validate(assertion.getSignature());
            }
        }
    }

    /**
     * Signs a STORK AuthnRequest
     *
     * @param storkAuthnRequest
     *            STORK AuthRequest to sign
     * @return Signed STORK AuthnRequest
     * @throws SecurityException
     * @throws SAMLException
     */
    private STORKAuthnRequest signSTORKAuthnRequest(STORKAuthnRequest storkAuthnRequest) throws SecurityException, SAMLException {
        Credential credential = keyManager.resolveSingle(new CriteriaSet(new EntityIDCriteria(issuer)));
        ;
        SAMLUtil.signSAMLObject(storkAuthnRequest, credential);
        return storkAuthnRequest;
    }

    private List<RequestedAttribute> getRequestedAttributes() throws Exception {
        List<RequestedAttribute> requestedAttributeList = new ArrayList<RequestedAttribute>();
        if (requestedAttributeNames.length != requestedAttributeMandatoryValues.length) {
            throw new Exception("sp.requested_attributes.names"
                    + " and " + "sp.requested_attributes.mandatory_values" + " differ in length. Check configuration file.");
        }
        for (int i = 0; i < requestedAttributeNames.length; i++) {
            String name = STORKConstants.STORK_ATTRIBUTE_NAME_PREFIX + requestedAttributeNames[i];
            boolean isRequired = Boolean.parseBoolean(requestedAttributeMandatoryValues[i]);
            String value = requestedAttributeOptionalValues.length == 0 ? null : requestedAttributeOptionalValues[i];
            RequestedAttribute att = STORKMessagesBuilder.buildRequestedAttribute(name, isRequired, value);
            requestedAttributeList.add(att);
        }
        return requestedAttributeList;
    }
}
