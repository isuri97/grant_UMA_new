package org.wso2.carbon.identity.uma.grant.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

/**
 * Created by isuri on 2/1/18.
 */
public class UMAGrant  extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(UMAGrant.class);

    public static final String UMA_GRANT_PARAM = "urn:ietf:params:oauth:grant-type:uma-ticket";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws
            IdentityOAuth2Exception{

        log.info("UMA Grant handler is hit");

        if(!super.validateGrant(oAuthTokenReqMessageContext)){
            return false;
        }

        log.debug("UMA Grant handler is hit");

        OAuth2AccessTokenReqDTO tokenReqDTO = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO();
        String refreshToken = null;


        boolean authStatus = false;

        String grantType = null;
        String grantTypeSample = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();


        //Extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        for(RequestParameter parameter : parameters){
            if(UMA_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().equals(UMA_GRANT_PARAM)){
                    grantType = parameter.getValue()[0];
                }
            }
        }

        if(grantType == null) {

            ResponseHeader responseHeader = new ResponseHeader();
            responseHeader.setKey("SampleHeader-999");
            responseHeader.setValue("Provided Grant Type is Invalid.");
            oAuthTokenReqMessageContext.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});

        }else {
            //validate grant Type
            authStatus = isValidGrantType(grantType);

            if(authStatus){


            }
        }


        return authStatus;
    }

    private boolean isValidGrantType(String grantType){

        return false;
    }
}
