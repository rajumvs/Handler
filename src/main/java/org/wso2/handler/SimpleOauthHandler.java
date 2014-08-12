package org.wso2.handler;

/**
 * Created with IntelliJ IDEA.
 * User: dinuka
 * Date: 4/4/13
 * Time: 3:46 PM
 * To change this template use File | Settings | File Templates.
 */
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.http.HttpHeaders;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.identity.oauth2.stub.OAuth2ServiceStub;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.rest.AbstractHandler;

import java.util.Map;

public class SimpleOauthHandler extends AbstractHandler implements ManagedLifecycle {

    private String securityHeader = HttpHeaders.AUTHORIZATION;
    private String consumerKeyHeaderSegment = "Bearer";
    private String oauthHeaderSplitter = ",";
    private String consumerKeySegmentDelimiter = " ";
    private String oauth2TokenValidationService = "oauth2TokenValidationService";
    private String identityServerUserName = "identityServerUserName";
    private String identityServerPw = "identityServerPw";
    private String oAuth2Service = "oauth2Service";
 
    @Override
    public boolean handleRequest(MessageContext messageContext) {
        try{
            ConfigurationContext configCtx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
            //Read parameters from axis2.xml
            String identityServerUrl = messageContext.getConfiguration().getAxisConfiguration().getParameter(oauth2TokenValidationService).getValue().toString();
            String username = messageContext.getConfiguration().getAxisConfiguration().getParameter(identityServerUserName).getValue().toString();
            String password = messageContext.getConfiguration().getAxisConfiguration().getParameter(identityServerPw).getValue().toString();
 
            OAuth2TokenValidationServiceStub stub = new OAuth2TokenValidationServiceStub(configCtx,identityServerUrl);
             
            String oauth2ServiceUrl = messageContext.getConfiguration().getAxisConfiguration().getParameter(oAuth2Service).getValue().toString();
            OAuth2ServiceStub oAuth2ServiceStub = new OAuth2ServiceStub(configCtx,oauth2ServiceUrl);
             
             
            ServiceClient client = stub._getServiceClient();
            Options options = client.getOptions();
            HttpTransportProperties.Authenticator authenticator = new HttpTransportProperties.Authenticator();
            authenticator.setUsername(username);
            authenticator.setPassword(password);
            authenticator.setPreemptiveAuthentication(true);
 
            options.setProperty(HTTPConstants.AUTHENTICATE, authenticator);
            client.setOptions(options);
            OAuth2TokenValidationRequestDTO dto = new OAuth2TokenValidationRequestDTO();
           // dto.set("bearer");
            Map headers = (Map) ((Axis2MessageContext) messageContext).getAxis2MessageContext().
                    getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
            String apiKey = null;
            if (headers != null) {
                apiKey = extractCustomerKeyFromAuthHeader(headers);
            }
            OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessToken = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
            accessToken.setTokenType("bearer");
            accessToken.setIdentifier(apiKey);
            dto.setAccessToken(accessToken);
            //validate passed apiKey(token)
            if (stub.validate(dto).getValid()) {
                String user = stub.validate(dto).getAuthorizedUser();
                System.out.println(user);
                user = user.substring(12, user.indexOf('@'));
                System.out.println(username);
                org.apache.axis2.context.MessageContext msgContext;
                Axis2MessageContext axis2Msgcontext = null;
                axis2Msgcontext = (Axis2MessageContext) messageContext;
                msgContext = axis2Msgcontext.getAxis2MessageContext();
                msgContext.setProperty("username", user);
                return true;
            }else{
                return false;
            }
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
    }
 
    public String extractCustomerKeyFromAuthHeader(Map headersMap) {
 
        // From 1.0.7 version of this component onwards remove the OAuth
        // authorization header from
        // the message is configurable. So we dont need to remove headers at
        // this point.
        String authHeader = (String) headersMap.get(securityHeader);
        if (authHeader == null) {
            return null;
        }
 
        if (authHeader.startsWith("OAuth ") || authHeader.startsWith("oauth ")) {
            authHeader = authHeader.substring(authHeader.indexOf("o"));
        }
 
        String[] headers = authHeader.split(oauthHeaderSplitter);
        if (headers != null) {
            for (int i = 0; i < headers.length; i++) {
                String[] elements = headers[i].split(consumerKeySegmentDelimiter);
                if (elements != null && elements.length > 1) {
                    int j = 0;
                    boolean isConsumerKeyHeaderAvailable = false;
                    for (String element : elements) {
                        if (!"".equals(element.trim())) {
                            if (consumerKeyHeaderSegment.equals(elements[j].trim())) {
                                isConsumerKeyHeaderAvailable = true;
                            } else if (isConsumerKeyHeaderAvailable) {
                                return removeLeadingAndTrailing(elements[j].trim());
                            }
                        }
                        j++;
                    }
                }
            }
        }
        return null;
    }
 
    private String removeLeadingAndTrailing(String base) {
        String result = base;
 
        if (base.startsWith("\"") || base.endsWith("\"")) {
            result = base.replace("\"", "");
        }
        return result.trim();
    }
 
    @Override
    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }
 
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        // To change body of implemented methods use File | Settings | File
        // Templates.
    }
 
    @Override
    public void destroy() {
        // To change body of implemented methods use File | Settings | File
        // Templates.
    }
}
