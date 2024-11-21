/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.core.security.authc.saml;

import org.elasticsearch.common.settings.Setting;

import java.util.Set;

public class MultiProjectSpSamlRealmSettings {

    public static final String TYPE = "multi_project_saml";

    public static final String PREFIX = "xpack.security.authc.projects.";

    public static final Setting.AffixSetting<String> SP_ENTITY_ID = projectSetting("sp.entity_id");
    public static final Setting.AffixSetting<String> SP_ACS = projectSetting("sp.acs");
    public static final Setting.AffixSetting<String> SP_LOGOUT = projectSetting("sp.logout");

    private static Setting.AffixSetting<String> projectSetting(String suffix) {
        return Setting.affixKeySetting(
            PREFIX,
            suffix,
            key -> Setting.simpleString(key, Setting.Property.NodeScope, Setting.Property.Dynamic)
        );
    }

    public static <T> Setting<T> getProjectSetting(Setting.AffixSetting<T> setting, String projectId) {
        return setting.getConcreteSettingForNamespace(projectId);
    }

    public static Set<Setting.AffixSetting<?>> getSettings() {
        Set<Setting.AffixSetting<?>> samlSettings = SamlRealmSettings.getSettings(TYPE);
        samlSettings.add(SP_ENTITY_ID);
        samlSettings.add(SP_ACS);
        samlSettings.add(SP_LOGOUT);

        return samlSettings;
    }
}
