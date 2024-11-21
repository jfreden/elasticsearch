/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.authc.saml;

import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.authc.saml.MultiProjectSpSamlRealmSettings;
import org.opensaml.security.x509.X509Credential;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.elasticsearch.xpack.core.security.authc.saml.MultiProjectSpSamlRealmSettings.SP_ACS;
import static org.elasticsearch.xpack.core.security.authc.saml.MultiProjectSpSamlRealmSettings.SP_ENTITY_ID;
import static org.elasticsearch.xpack.core.security.authc.saml.MultiProjectSpSamlRealmSettings.SP_LOGOUT;
import static org.elasticsearch.xpack.core.security.authc.saml.SamlRealmSettings.REQUESTED_AUTHN_CONTEXT_CLASS_REF;
import static org.elasticsearch.xpack.security.authc.saml.SamlRealm.buildEncryptionCredential;
import static org.elasticsearch.xpack.security.authc.saml.SamlRealm.buildSigningConfiguration;

/**
 * A simple container class that holds all configuration related to a SAML Service Provider (SP).
 */
public class MultiProjectSamlSpConfiguration implements SpConfiguration {
    private final ThreadPool threadPool;
    private final SigningConfiguration signingConfiguration;
    private final List<String> reqAuthnCtxClassRef;
    private final List<X509Credential> encryptionCredentials;
    private final AtomicReference<Settings> settings = new AtomicReference<>();

    private MultiProjectSamlSpConfiguration(
        ThreadPool threadPool,
        SigningConfiguration signingConfiguration,
        List<X509Credential> encryptionCredentials,
        List<String> reqAuthnCtxClassRef,
        Settings settings
    ) {
        this.threadPool = threadPool;
        this.signingConfiguration = signingConfiguration;
        this.reqAuthnCtxClassRef = reqAuthnCtxClassRef;
        this.encryptionCredentials = encryptionCredentials;
        this.settings.set(settings);
    }

    public static MultiProjectSamlSpConfiguration create(ThreadPool threadPool, RealmConfig realmConfig, ClusterSettings clusterSettings)
        throws GeneralSecurityException, IOException {
        List<X509Credential> encryptionCredential = buildEncryptionCredential(realmConfig);

        MultiProjectSamlSpConfiguration projectSamlServiceProviderConfiguration = new MultiProjectSamlSpConfiguration(
            threadPool,
            buildSigningConfiguration(realmConfig),
            encryptionCredential != null ? encryptionCredential : Collections.<X509Credential>emptyList(),
            realmConfig.getSetting(REQUESTED_AUTHN_CONTEXT_CLASS_REF),
            getServiceProviderSettings(realmConfig)
        );

        clusterSettings.addAffixGroupUpdateConsumer(
            List.of(
                MultiProjectSpSamlRealmSettings.SP_ENTITY_ID,
                MultiProjectSpSamlRealmSettings.SP_ACS,
                MultiProjectSpSamlRealmSettings.SP_LOGOUT
            ),
            (key, settings) -> {
                Settings.Builder settingsBuilder = Settings.builder();
                settingsBuilder.put(projectSamlServiceProviderConfiguration.settings.get());
                settingsBuilder.put(settings);
                projectSamlServiceProviderConfiguration.settings.set(settingsBuilder.build());
            }
        );
        return projectSamlServiceProviderConfiguration;
    }

    private static Settings getServiceProviderSettings(RealmConfig realmConfig) {
        Settings.Builder settingsBuilder = Settings.builder();
        Stream.of(
            MultiProjectSpSamlRealmSettings.SP_ENTITY_ID,
            MultiProjectSpSamlRealmSettings.SP_ACS,
            MultiProjectSpSamlRealmSettings.SP_LOGOUT
        )
            .flatMap(setting -> setting.getAllConcreteSettings(realmConfig.settings()))
            .forEach(s -> settingsBuilder.put(s.getKey(), s.get(realmConfig.settings())));
        return settingsBuilder.build();
    }

    private <T> T require(Setting.AffixSetting<T> setting, String projectId) {
        Setting<T> projectScopedSetting = MultiProjectSpSamlRealmSettings.getProjectSetting(setting, projectId);
        T value = projectScopedSetting.get(settings.get());
        if (value == null) {
            throw new IllegalArgumentException("The configuration setting [" + projectScopedSetting.getKey() + "] is required");
        }
        return value;
    }

    public String getEntityId() {
        String projectId = threadPool.getThreadContext().getHeader("X-Elastic-Project-Id");
        if (projectId == null) {
            throw new IllegalArgumentException("Project ID required for project saml realm");
        }
        return require(SP_ENTITY_ID, projectId);
    }

    public String getAscUrl() {
        String projectId = threadPool.getThreadContext().getHeader("X-Elastic-Project-Id");
        if (projectId == null) {
            throw new IllegalArgumentException("Project ID required for project saml realm");
        }
        return require(SP_ACS, projectId);
    }

    public String getLogoutUrl() {
        String projectId = threadPool.getThreadContext().getHeader("X-Elastic-Project-Id");
        if (projectId == null) {
            throw new IllegalArgumentException("Project ID required for project saml realm");
        }
        return require(SP_LOGOUT, projectId);
    }

    public List<X509Credential> getEncryptionCredentials() {
        return encryptionCredentials;
    }

    public SigningConfiguration getSigningConfiguration() {
        return signingConfiguration;
    }

    public List<String> getReqAuthnCtxClassRef() {
        return reqAuthnCtxClassRef;
    }
}
