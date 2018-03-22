package org.wso2.carbon.identity.uma.grant.sample;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by isuri on 2/1/18.
 */
public class UMAGrantValidator extends AbstractValidator<HttpServletRequest> {

    public UMAGrantValidator (){
        requiredParams.add(grantSample.UMA_GRANT_PARAM);

    }

}
