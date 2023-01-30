package com.p3solutions.archon_authentication_service.core.authentication.security.saml.core;

import org.apache.commons.lang.StringUtils;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Service to extract the required information from the SAML response
 * @author seelan
 */
@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

	private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

	@Autowired
	private Environment environment;

	@Value(value = "${saml.attribute.firstname}")
	private String firstNameAttribute;

	@Value(value = "${saml.attribute.lastname}")
	private String lastNameAttribute;

	@Value(value = "${saml.attribute.email}")
	private String emailAttribute;
	
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
		
		String userID = credential.getNameID().getValue();

		LOG.info(userID + " is logged in");
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		authorities.add(authority);

		List<String> roleList=getRoles(credential);
		roleList.forEach(st ->{
			GrantedAuthority authoritySSO = new SimpleGrantedAuthority(st);
			authorities.add(authoritySSO);
		});

		XMLObject assertion = credential.getAuthenticationAssertion().getParent();
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		try {
			transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		} catch (Exception e) {
			LOG.error(" Set Attribute Error :"+e.getMessage(),e);
		}
		try {
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(assertion.getDOM());
			StreamResult result = new StreamResult(new StringWriter());
			transformer.transform(source, result);
		} catch (TransformerConfigurationException e) {
			//e.printStackTrace();
			LOG.error(" Set Attribute Error :"+e.getMessage(),e);
		} catch (TransformerException e) {
			//e.printStackTrace();
			LOG.error(" Set Attribute Error :"+e.getMessage(),e);
		}

		String firstName=credential.getAttributeAsString(firstNameAttribute);
		String lastName=credential.getAttributeAsString(lastNameAttribute);
		String email=credential.getAttributeAsString(emailAttribute);

		if(StringUtils.isNotBlank(firstName)) {
			GrantedAuthority authoritySSO1 = new SimpleGrantedAuthority("firstName:"+firstName);
			authorities.add(authoritySSO1);
		}
		if(StringUtils.isNotBlank(lastName)) {
			GrantedAuthority authoritySSO2 = new SimpleGrantedAuthority("lastName:"+lastName);
			authorities.add(authoritySSO2);
		}
		if(StringUtils.isNotBlank(email)) {
			GrantedAuthority authoritySSO3 = new SimpleGrantedAuthority("email:"+email);
			authorities.add(authoritySSO3);
		}

		return new User(userID, "<abc123>", true, true, true, true, authorities);
	}

	private List<String> getRoles(SAMLCredential credential) {
		List<String> roleList = new LinkedList();
		for (org.opensaml.saml2.core.Attribute attr : credential.getAttributes()) {
			String fname = attr.getName();
			String samlRoleName=environment.getRequiredProperty("saml.role.name");
			if (!StringUtils.isEmpty(fname) && fname.equals(samlRoleName)) {
				List<XMLObject> allAttr = attr.getAttributeValues();
				if (allAttr != null && !allAttr.isEmpty()) {
					for (XMLObject xmlobj : allAttr) {
						roleList.add(getAttributeValue(xmlobj));
					}
				}
//				roleList.add(getAttributeValue(attr.getAttributeValues().get(0)));
			}
		}
		LOG.debug(" roleList {}",roleList);
		return roleList;
	}

	private String getAttributeValue(XMLObject attributeValue) {
		return attributeValue == null ? null
				: attributeValue instanceof XSString ? getStringAttributeValue((XSString) attributeValue)
				: attributeValue instanceof XSAnyImpl ? getAnyAttributeValue((XSAnyImpl) attributeValue)
				: attributeValue.toString();
	}

	private String getAnyAttributeValue(XSAnyImpl attributeValue) {
		return attributeValue.getTextContent();
	}

	private String getStringAttributeValue(XSString attributeValue) {
		return attributeValue.getValue();
	}
}
