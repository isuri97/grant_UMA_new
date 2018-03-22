package org.wso2.carbon.identity.uma.grant.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

/**
 * Created by isuri on 3/22/18.
 */
public class grantSample extends AbstractAuthorizationGrantHandler {

    public static final String UMA_GRANT_PARAM = "grantType";
    private static Log log = LogFactory.getLog(grantSample.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        log.info("in grantSample validateGrant method. ");

        if (!super.validateGrant(tokReqMsgCtx)) {
            return false;
        }

        log.debug("in EssentialRefreshGrantHandler validateGrant method 2");

        boolean authStatus = false;

        //String grantType1 = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        String grantType = null;

        for (RequestParameter parameter : parameters) {
            if (UMA_GRANT_PARAM.equals(parameter.getKey())) {
                    grantType = parameter.getValue()[0];
                }
                log.debug("key=" + parameter.getKey() + " value=" + parameter.getValue()[0]);
            }


        if (grantType != null) {

            authStatus = isValidGrantType(grantType);

            if (authStatus) {

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(grantType);
                tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
                tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
            } else {

                ResponseHeader responseHeader = new ResponseHeader();
                responseHeader.setKey("SampleHeader-999");
                responseHeader.setValue("Provided Grant Type is Invalid.");
                tokReqMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});

            }
        }
        return authStatus;
    }

    private boolean isValidGrantType(String grantType) {

        if (grantType.equals("urn:ietf:params:oauth:grant-type:uma-ticket")) {
            return true;
        }
        return false;
    }

}

