/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.authenticator.saml2.sso.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * This class is used as the singleton data holder inside SAML2 SSO Authenticator BE module.
 */
public class SAML2SSOAuthBEDataHolder {
    private static SAML2SSOAuthBEDataHolder instance = new SAML2SSOAuthBEDataHolder();

    private RealmService realmService;
    private BundleContext bundleContext;
    private String idPCertAlias;

    private SAML2SSOAuthBEDataHolder() {
    }

    public static SAML2SSOAuthBEDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public BundleContext getBundleContext() {
        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public String getIdPCertAlias() {
        return idPCertAlias;
    }

    public void setIdPCertAlias(String idPCertAlias) {
        this.idPCertAlias = idPCertAlias;
    }
}
