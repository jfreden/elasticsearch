/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.support;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.features.NodeFeature;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.reindex.UpdateByQueryAction;
import org.elasticsearch.index.reindex.UpdateByQueryRequest;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptType;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.xpack.core.security.action.rolemapping.DeleteRoleMappingAction;
import org.elasticsearch.xpack.core.security.action.rolemapping.DeleteRoleMappingRequestBuilder;
import org.elasticsearch.xpack.core.security.action.rolemapping.GetRoleMappingsAction;
import org.elasticsearch.xpack.core.security.action.rolemapping.GetRoleMappingsRequestBuilder;
import org.elasticsearch.xpack.core.security.authc.support.mapper.ExpressionRoleMapping;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.elasticsearch.TransportVersions.ADD_MANAGE_ROLES_PRIVILEGE;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.executeAsyncWithOrigin;
import static org.elasticsearch.xpack.security.support.SecuritySystemIndices.SecurityMainIndexMappingVersion.ADD_REMOTE_CLUSTER_AND_DESCRIPTION_FIELDS;

public class SecurityMigrations {

    /**
     * Interface for creating SecurityMigrations that will be automatically applied once to existing .security indices
     * IMPORTANT: A new index version needs to be added to {@link org.elasticsearch.index.IndexVersions} for the migration to be triggered
     */
    public interface SecurityMigration {
        /**
         * Method that will execute the actual migration - needs to be idempotent and non-blocking
         *
         * @param indexManager for the security index
         * @param client the index client
         * @param listener listener to provide updates back to caller
         */
        void migrate(SecurityIndexManager indexManager, Client client, ActionListener<Void> listener);

        /**
         * Any node features that are required for this migration to run. This makes sure that all nodes in the cluster can handle any
         * changes in behaviour introduced by the migration.
         *
         * @return a set of features needed to be supported or an empty set if no change in behaviour is expected
         */
        Set<NodeFeature> nodeFeaturesRequired();

        /**
         * Check that any pre-conditions are met before launching migration
         *
         * @param securityIndexManagerState current state of the security index
         * @return true if pre-conditions met, otherwise false
         */
        default boolean checkPreConditions(SecurityIndexManager.State securityIndexManagerState) {
            return true;
        }

        /**
         * The min mapping version required to support this migration. This makes sure that the index has at least the min mapping that is
         * required to support the migration.
         *
         * @return the minimum mapping version required to apply this migration
         */
        int minMappingVersion();
    }

    public static final Integer ROLE_METADATA_FLATTENED_MIGRATION_VERSION = 1;
    public static final Integer CLEANUP_ROLE_MAPPING_DUPLICATES_MIGRATION_VERSION = 2;
    private static final Logger logger = LogManager.getLogger(SecurityMigration.class);

    public static final TreeMap<Integer, SecurityMigration> MIGRATIONS_BY_VERSION = new TreeMap<>(
        Map.of(
            ROLE_METADATA_FLATTENED_MIGRATION_VERSION,
            new RoleMetadataFlattenedMigration(),
            CLEANUP_ROLE_MAPPING_DUPLICATES_MIGRATION_VERSION,
            new CleanupRoleMappingDuplicatesMigration()
        )
    );

    public static class RoleMetadataFlattenedMigration implements SecurityMigration {
        @Override
        public void migrate(SecurityIndexManager indexManager, Client client, ActionListener<Void> listener) {
            BoolQueryBuilder filterQuery = new BoolQueryBuilder().filter(QueryBuilders.termQuery("type", "role"))
                .mustNot(QueryBuilders.existsQuery("metadata_flattened"));
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(filterQuery).size(0).trackTotalHits(true);
            SearchRequest countRequest = new SearchRequest(indexManager.getConcreteIndexName());
            countRequest.source(searchSourceBuilder);

            client.search(countRequest, ActionListener.wrap(response -> {
                // If there are no roles, skip migration
                if (response.getHits().getTotalHits().value > 0) {
                    logger.info("Preparing to migrate [" + response.getHits().getTotalHits().value + "] roles");
                    updateRolesByQuery(indexManager, client, filterQuery, listener);
                } else {
                    listener.onResponse(null);
                }
            }, listener::onFailure));
        }

        private void updateRolesByQuery(
            SecurityIndexManager indexManager,
            Client client,
            BoolQueryBuilder filterQuery,
            ActionListener<Void> listener
        ) {
            UpdateByQueryRequest updateByQueryRequest = new UpdateByQueryRequest(indexManager.getConcreteIndexName());
            updateByQueryRequest.setQuery(filterQuery);
            updateByQueryRequest.setScript(
                new Script(ScriptType.INLINE, "painless", "ctx._source.metadata_flattened = ctx._source.metadata", Collections.emptyMap())
            );
            client.admin()
                .cluster()
                .execute(UpdateByQueryAction.INSTANCE, updateByQueryRequest, ActionListener.wrap(bulkByScrollResponse -> {
                    logger.info("Migrated [" + bulkByScrollResponse.getTotal() + "] roles");
                    listener.onResponse(null);
                }, listener::onFailure));
        }

        @Override
        public Set<NodeFeature> nodeFeaturesRequired() {
            return Set.of(SecuritySystemIndices.SECURITY_ROLES_METADATA_FLATTENED);
        }

        @Override
        public int minMappingVersion() {
            return ADD_REMOTE_CLUSTER_AND_DESCRIPTION_FIELDS.id();
        }
    }

    public static class CleanupRoleMappingDuplicatesMigration implements SecurityMigration {
        @Override
        public void migrate(SecurityIndexManager indexManager, Client client, ActionListener<Void> listener) {
            getRoleMappings(client, ActionListener.wrap(roleMappings -> {
                List<String> roleMappingsToDelete = getDuplicateRoleMappingNames(roleMappings);
                if (roleMappingsToDelete.isEmpty() == false) {
                    logger.info("Found [" + roleMappingsToDelete.size() + "] role mappings to cleanup in .security index.");
                    deleteNativeRoleMappings(client, roleMappingsToDelete.iterator(), listener);
                } else {
                    listener.onResponse(null);
                }
            }, listener::onFailure));
        }

        private void getRoleMappings(Client client, ActionListener<ExpressionRoleMapping[]> listener) {
            executeAsyncWithOrigin(
                client,
                SECURITY_ORIGIN,
                GetRoleMappingsAction.INSTANCE,
                new GetRoleMappingsRequestBuilder(client).request(),
                ActionListener.wrap(response -> listener.onResponse(response.mappings()), listener::onFailure)
            );
        }

        private void deleteNativeRoleMappings(Client client, Iterator<String> namesIterator, ActionListener<Void> listener) {
            String name = namesIterator.next();
            boolean hasNext = namesIterator.hasNext();
            executeAsyncWithOrigin(
                client,
                SECURITY_ORIGIN,
                DeleteRoleMappingAction.INSTANCE,
                new DeleteRoleMappingRequestBuilder(client).name(name).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE).request(),
                ActionListener.wrap(response -> {
                    if (response.isFound() == false) {
                        logger.warn("Expected role mapping [" + name + "] not found during role mapping clean up.");
                    } else {
                        logger.info("Deleted duplicated role mapping [" + name + "] from .security index");
                    }
                    if (hasNext) {
                        deleteNativeRoleMappings(client, namesIterator, listener);
                    } else {
                        listener.onResponse(null);
                    }
                }, exception -> {
                    logger.warn("Failed to delete role mapping [" + name + "]", exception);
                    if (hasNext) {
                        // Continue even if some deletions fail to do as much cleanup as possible
                        deleteNativeRoleMappings(client, namesIterator, listener);
                    } else {
                        listener.onFailure(exception);
                    }
                })
            );
        }

        @Override
        public boolean checkPreConditions(SecurityIndexManager.State securityIndexManagerState) {
            // If there are operator defined role mappings, make sure they've been loaded in to cluster state before launching migration
            return securityIndexManagerState.readyForRoleMappingCleanupMigration;
        }

        @Override
        public Set<NodeFeature> nodeFeaturesRequired() {
            return Set.of(SecuritySystemIndices.SECURITY_ROLE_MAPPING_CLEANUP);
        }

        @Override
        public int minMappingVersion() {
            return ADD_MANAGE_ROLES_PRIVILEGE.id();
        }

        // TODO REMOVE AND USE CONSTANT WHEN AVAILABLE!
        public static final String METADATA_READ_ONLY_FLAG_KEY = "_read_only";
        public static final String RESERVED_ROLE_MAPPING_SUFFIX = "(read only)";

        // Visible for testing
        protected static List<String> getDuplicateRoleMappingNames(ExpressionRoleMapping... roleMappings) {
            // Partition role mappings on if they're cluster state role mappings (true) or native role mappings (false)
            Map<Boolean, List<ExpressionRoleMapping>> partitionedRoleMappings = Arrays.stream(roleMappings)
                .collect(
                    Collectors.partitioningBy(
                        roleMapping -> roleMapping.getMetadata().get(METADATA_READ_ONLY_FLAG_KEY) != null
                            && (boolean) roleMapping.getMetadata().get(METADATA_READ_ONLY_FLAG_KEY)
                    )
                );

            Set<String> clusterStateRoleMappings = partitionedRoleMappings.get(true)
                .stream()
                .map(ExpressionRoleMapping::getName)
                .map(name -> {
                    int lastIndex = name.lastIndexOf(RESERVED_ROLE_MAPPING_SUFFIX);
                    return lastIndex > 0 ? name.substring(0, lastIndex) : name;
                })
                .collect(Collectors.toSet());

            return partitionedRoleMappings.get(false)
                .stream()
                .map(ExpressionRoleMapping::getName)
                .filter(clusterStateRoleMappings::contains)
                .toList();
        }
    }
}
