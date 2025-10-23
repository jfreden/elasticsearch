/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.remotecluster;

import io.netty.handler.codec.http.HttpMethod;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.common.io.Streams;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Strings;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchResponseUtils;
import org.elasticsearch.test.cluster.ElasticsearchCluster;
import org.elasticsearch.test.cluster.LogType;
import org.elasticsearch.test.cluster.util.resource.Resource;
import org.junit.ClassRule;
import org.junit.rules.RuleChain;
import org.junit.rules.TestRule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

public class RemoteClusterSecurityCrossClusterAuditIT extends AbstractRemoteClusterSecurityTestCase {

    private static final AtomicReference<Map<String, Object>> MY_REMOTE_API_KEY_MAP_REF = new AtomicReference<>();
    private static final String TEST_ACCESS_JSON = """
        {
            "search": [
              {
                "names": ["index*", "not_found_index"]
              }
            ]
        }""";
    private static final String[] MATCHING_CERTIFICATE_IDENTITY_PATTERNS = new String[] {
        "CN=instance",
        "^CN=instance$",
        "(?i)" + "^CN=instance$",
        "^CN=[A-Za-z0-9_]+$" };

    static {
        fulfillingCluster = ElasticsearchCluster.local()
            .name("fulfilling-cluster")
            .apply(commonClusterConfig)
            .setting("remote_cluster_server.enabled", "true")
            .setting("remote_cluster.port", "0")
            .setting("xpack.security.remote_cluster_server.ssl.enabled", "true")
            .setting("xpack.security.remote_cluster_server.ssl.key", "remote-cluster.key")
            .setting("xpack.security.remote_cluster_server.ssl.certificate", "remote-cluster.crt")
            .setting("xpack.security.audit.enabled", "true")
            .setting(
                "xpack.security.audit.logfile.events.include",
                "[authentication_success, authentication_failed, access_denied, access_granted]"
            )
            .setting("logger.org.elasticsearch.xpack.core", "debug") // useful for human debugging
            .setting("logger.org.elasticsearch.xpack.security", "debug") // useful for human debugging
            .configFile("signing_ca.crt", Resource.fromClasspath("signing/root.crt"))
            .keystore("xpack.security.remote_cluster_server.ssl.secure_key_passphrase", "remote-cluster-password")
            .build();

        queryCluster = ElasticsearchCluster.local()
            .name("query-cluster")
            .apply(commonClusterConfig)
            .setting("xpack.security.remote_cluster_client.ssl.enabled", "true")
            .setting("xpack.security.remote_cluster_client.ssl.certificate_authorities", "remote-cluster-ca.crt")
            .configFile("signing.crt", Resource.fromClasspath("signing/signing.crt"))
            .configFile("signing.key", Resource.fromClasspath("signing/signing.key"))
            .keystore("cluster.remote.my_remote_cluster.credentials", () -> {
                if (MY_REMOTE_API_KEY_MAP_REF.get() == null) {
                    MY_REMOTE_API_KEY_MAP_REF.set(
                        createCrossClusterAccessApiKey(TEST_ACCESS_JSON, randomFrom(MATCHING_CERTIFICATE_IDENTITY_PATTERNS))
                    );
                }
                return (String) MY_REMOTE_API_KEY_MAP_REF.get().get("encoded");
            })
            .keystore("cluster.remote.invalid_remote.credentials", randomEncodedApiKey())
            .build();
    }

    @ClassRule
    // Use a RuleChain to ensure that fulfilling cluster is started before query cluster
    public static TestRule clusterRule = RuleChain.outerRule(fulfillingCluster).around(queryCluster);

    public void testCrossClusterSearchWithCrossClusterApiKeySigning() throws Exception {
        updateClusterSettings(
            Settings.builder()
                .put("cluster.remote.my_remote_cluster.signing.certificate", "signing.crt")
                .put("cluster.remote.my_remote_cluster.signing.key", "signing.key")
                .build()
        );

        updateClusterSettingsFulfillingCluster(
            Settings.builder().put("cluster.remote.signing.certificate_authorities", "signing_ca.crt").build()
        );

        indexTestData();

        // Make sure we can search if cert trusted
        {
            assertCrossClusterSearchSuccessfulWithResult();
        }

        // Test API key with non-matching certificate identity is rejected
        {
            var nonMatchingCertificateIdentity = randomFrom("", "no-match", "^CN= instance$", "^CN=instance.$", "^cn=instance$");
            updateCrossClusterAccessApiKey(nonMatchingCertificateIdentity);
            assertCrossClusterAuthFail(
                "DN from provided certificate [CN=instance] does not match API Key certificate identity pattern ["
                    + nonMatchingCertificateIdentity
                    + "]"
            );
            // Reset
            updateCrossClusterAccessApiKey(randomFrom(MATCHING_CERTIFICATE_IDENTITY_PATTERNS));
        }

        Thread.sleep(5000);

        // TODO We could use assertBusy() until we see the log we're looking for
        for (int i = 0; i < fulfillingCluster.getNumNodes(); i++) {
            try (var auditLog = fulfillingCluster.getNodeLog(i, LogType.AUDIT)) {
                final List<String> lines = Streams.readAllLines(auditLog);
                logger.info("Audit log [NODE {}] [{}]", i, lines);
            }
        }
    }

    private void assertCrossClusterAuthFail(String expectedMessage) {
        var responseException = assertThrows(ResponseException.class, () -> simpleCrossClusterSearch(randomBoolean()));
        assertThat(responseException.getResponse().getStatusLine().getStatusCode(), equalTo(401));
        assertThat(responseException.getMessage(), containsString(expectedMessage));
    }

    private void assertCrossClusterSearchSuccessfulWithResult() throws IOException {
        boolean alsoSearchLocally = randomBoolean();
        final Response response = simpleCrossClusterSearch(alsoSearchLocally);
        assertOK(response);
        final SearchResponse searchResponse;
        try (var parser = responseAsParser(response)) {
            searchResponse = SearchResponseUtils.parseSearchResponse(parser);
        }
        try {
            final List<String> actualIndices = Arrays.stream(searchResponse.getHits().getHits())
                .map(SearchHit::getIndex)
                .collect(Collectors.toList());
            if (alsoSearchLocally) {
                assertThat(actualIndices, containsInAnyOrder("index1", "local_index"));
            } else {
                assertThat(actualIndices, containsInAnyOrder("index1"));
            }
        } finally {
            searchResponse.decRef();
        }
    }

    private Response simpleCrossClusterSearch(boolean alsoSearchLocally) throws IOException {
        final var searchRequest = new Request(
            "GET",
            String.format(
                Locale.ROOT,
                "/%s%s:%s/_search?ccs_minimize_roundtrips=%s",
                alsoSearchLocally ? "local_index," : "",
                randomFrom("my_remote_cluster", "*", "my_remote_*"),
                randomFrom("index1", "*"),
                randomBoolean()
            )
        );
        return performRequestWithRemoteAccessUser(searchRequest);
    }

    private void indexTestData() throws Exception {
        configureRemoteCluster();

        // Fulfilling cluster
        {
            // Index some documents, so we can attempt to search them from the querying cluster
            final Request bulkRequest = new Request("POST", "/_bulk?refresh=true");
            bulkRequest.setJsonEntity(Strings.format("""
                { "index": { "_index": "index1" } }
                { "foo": "bar" }
                { "index": { "_index": "index2" } }
                { "bar": "foo" }
                { "index": { "_index": "prefixed_index" } }
                { "baz": "fee" }\n"""));
            assertOK(performRequestAgainstFulfillingCluster(bulkRequest));
        }

        // Query cluster
        {
            // Index some documents, to use them in a mixed-cluster search
            final var indexDocRequest = new Request("POST", "/local_index/_doc?refresh=true");
            indexDocRequest.setJsonEntity("{\"local_foo\": \"local_bar\"}");
            assertOK(client().performRequest(indexDocRequest));

            // Create user role with privileges for remote and local indices
            final var putRoleRequest = new Request("PUT", "/_security/role/" + REMOTE_SEARCH_ROLE);
            putRoleRequest.setJsonEntity("""
                {
                  "description": "role with privileges for remote and local indices",
                  "cluster": ["manage_own_api_key"],
                  "indices": [
                    {
                      "names": ["local_index"],
                      "privileges": ["read"]
                    }
                  ],
                  "remote_indices": [
                    {
                      "names": ["index1", "not_found_index", "prefixed_index"],
                      "privileges": ["read", "read_cross_cluster"],
                      "clusters": ["my_remote_cluster"]
                    }
                  ]
                }""");
            assertOK(adminClient().performRequest(putRoleRequest));
            final var putUserRequest = new Request("PUT", "/_security/user/" + REMOTE_SEARCH_USER);
            putUserRequest.setJsonEntity("""
                {
                  "password": "x-pack-test-password",
                  "roles" : ["remote_search"]
                }""");
            assertOK(adminClient().performRequest(putUserRequest));
        }
    }

    private void updateClusterSettingsFulfillingCluster(Settings settings) throws IOException {
        final var request = newXContentRequest(HttpMethod.PUT, "/_cluster/settings", (builder, params) -> {
            builder.startObject("persistent");
            settings.toXContent(builder, params);
            return builder.endObject();
        });

        performRequestWithAdminUser(fulfillingClusterClient, request);
    }

    private Response performRequestWithRemoteAccessUser(final Request request) throws IOException {
        request.setOptions(RequestOptions.DEFAULT.toBuilder().addHeader("Authorization", basicAuthHeaderValue(REMOTE_SEARCH_USER, PASS)));
        return client().performRequest(request);
    }

    protected static Map<String, Object> createCrossClusterAccessApiKey(String accessJson, String certificateIdentity) {
        initFulfillingClusterClient();
        final var createCrossClusterApiKeyRequest = new Request("POST", "/_security/cross_cluster/api_key");
        createCrossClusterApiKeyRequest.setJsonEntity(Strings.format("""
            {
              "name": "cross_cluster_access_key",
              "certificate_identity": "%s",
              "access": %s
            }""", certificateIdentity, accessJson));
        try {
            final Response createCrossClusterApiKeyResponse = performRequestWithAdminUser(
                fulfillingClusterClient,
                createCrossClusterApiKeyRequest
            );
            assertOK(createCrossClusterApiKeyResponse);
            return responseAsMap(createCrossClusterApiKeyResponse);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    protected static Map<String, Object> updateCrossClusterAccessApiKey(String certificateIdentity) {
        initFulfillingClusterClient();
        final var createCrossClusterApiKeyRequest = new Request(
            "PUT",
            "/_security/cross_cluster/api_key/" + MY_REMOTE_API_KEY_MAP_REF.get().get("id")
        );
        createCrossClusterApiKeyRequest.setJsonEntity(
            "{\"certificate_identity\": " + (certificateIdentity != null ? "\"" + certificateIdentity + "\"" : "null") + "}"
        );
        try {
            final Response createCrossClusterApiKeyResponse = performRequestWithAdminUser(
                fulfillingClusterClient,
                createCrossClusterApiKeyRequest
            );
            assertOK(createCrossClusterApiKeyResponse);
            return responseAsMap(createCrossClusterApiKeyResponse);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
