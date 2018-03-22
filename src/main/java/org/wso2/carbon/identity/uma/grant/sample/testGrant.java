package org.wso2.carbon.identity.uma.grant.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

/**
 * Created by isuri on 3/23/18.
 */
public class testGrant extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(grantSample.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        log.info("in grantSample validateGrant method. ");

        if (!super.validateGrant(tokReqMsgCtx)) {
            return false;
        }

        log.debug("in EssentialRefreshGrantHandler validateGrant method 2");

        //String grantType1 = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();



        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();


        return false;
    }
}
