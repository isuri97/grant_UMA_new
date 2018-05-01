/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.uma.grant.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.uma.permission.service.dao.PermissionTicketDAO;
import org.wso2.carbon.identity.oauth.uma.permission.service.exception.UMAClientException;
import org.wso2.carbon.identity.oauth.uma.permission.service.exception.UMAServerException;
import org.wso2.carbon.identity.oauth.uma.permission.service.model.Resource;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.uma.resource.service.handler.XACMLHandler;

/**
 * Grant type for User Managed Access.
 */
public class UMAGrantType extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(UMAGrantType.class);
    public static final String UMA_GRANT_PARAM = "grantType";
    public static final String PERMISSION_TICKET = "permissionTicket";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("In UMAGrantType validateGrant method.");
        }
        if (!super.validateGrant(tokReqMsgCtx)) {
            return false;
        }
        boolean authStatus = false;
        //extract clientId from the tokenReqMessageContext
        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();

        // extract request parameters
        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        String grantType = null;
        String permissionTicket = null;
        boolean isMatched = false;

        // find out grant type
        for (RequestParameter parameter : parameters) {
            if (UMA_GRANT_PARAM.equals(parameter.getKey())) {
                if (parameter.getValue() != null) {
                    grantType = parameter.getValue()[0];
                }
            }

            // find out permission ticket
            if (PERMISSION_TICKET.equals(parameter.getKey())) {
                if (PERMISSION_TICKET.equals(parameter.getKey())) {
                    if (parameter.getValue() != null) {
                        permissionTicket = parameter.getValue()[0];
                        log.info("Obtained permission ticket");
                        isMatched = true;
                    }
                }
            }
        }

        if (grantType != null) {

            //validate grant type and permission ticket
            authStatus = isValidGrantType(grantType, permissionTicket, clientId);

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

    /**
     * @param grantType
     * @param permissionTicket
     * @return
     */
    private boolean isValidGrantType(String grantType, String permissionTicket, String clientId) throws
            IdentityOAuth2Exception {

        XACMLHandler XACMLHandler = new XACMLHandler();
        boolean isCheck = true;

        PermissionTicketDAO permissionTicketDAO = new PermissionTicketDAO();

        try {
            if (grantType.equals("urn:ietf:params:oauth:grant-type:uma-ticket")) {
                Resource resource = permissionTicketDAO.validatePermissionTicket(permissionTicket);
                log.info("Valid permission ticket :" + permissionTicket);
                if (XACMLHandler.isAuthouthorized(resource, clientId)) {
                    log.info("Resource get authorized.");
                    return true;
                }
                return false;
            }

        } catch (UMAClientException e) {
            log.error("client exception.");
        } catch (UMAServerException e) {
            log.error("server exception.");
        }
        return isCheck;
    }
}