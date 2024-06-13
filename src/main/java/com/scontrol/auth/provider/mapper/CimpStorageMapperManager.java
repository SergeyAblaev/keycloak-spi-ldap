/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.scontrol.auth.provider.mapper;

import com.scontrol.auth.provider.user.LDAPStorageProviderCimp;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ModelException;

/**
 * TODO: LDAPStorageMapper should be divided into more interfaces and let the LDAPStorageMapperManager to check which operation (feature) is supported by which mapper implementation
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CimpStorageMapperManager {

    private final LDAPStorageProviderCimp ldapProvider;

    public CimpStorageMapperManager(LDAPStorageProviderCimp ldapProvider) {
        this.ldapProvider = ldapProvider;
    }

    public LDAPStorageMapperCimp getMapper(ComponentModel mapperModel) {
        LDAPStorageMapperCimp ldapMapper = ldapProvider.getSession().getProvider(LDAPStorageMapperCimp.class, mapperModel);
        if (ldapMapper == null) {
            throw new ModelException("Can't find mapper type with ID: " + mapperModel.getProviderId());
        }

        return ldapMapper;
    }
}
