/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.action.user;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.TransportAction;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.sort.FieldSortBuilder;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.action.user.QueryUserAction;
import org.elasticsearch.xpack.core.security.action.user.QueryUserRequest;
import org.elasticsearch.xpack.core.security.action.user.QueryUserResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.authc.esnative.NativeUsersStore;
import org.elasticsearch.xpack.security.support.SecurityIndexBoolQueryBuilder;
import org.elasticsearch.xpack.security.support.SecurityIndexFieldNameTranslator;

import java.util.List;

import static org.elasticsearch.xpack.security.support.SecurityIndexFieldNameTranslator.exact;
import static org.elasticsearch.xpack.security.support.SecuritySystemIndices.SECURITY_MAIN_ALIAS;

public final class TransportQueryUserAction extends TransportAction<QueryUserRequest, QueryUserResponse> {
    private final NativeUsersStore usersStore;
    private final SecurityContext securityContext;

    private static final SecurityIndexFieldNameTranslator fieldNameTranslator = new SecurityIndexFieldNameTranslator(
        List.of(exact("name"), exact("username"), exact("roles"), exact("metadata"), exact("full_name"), exact("email"), exact("enabled"))
    );

    @Inject
    public TransportQueryUserAction(
        TransportService transportService,
        ActionFilters actionFilters,
        NativeUsersStore usersStore,
        SecurityContext context
    ) {
        super(QueryUserAction.NAME, actionFilters, transportService.getTaskManager());
        this.usersStore = usersStore;
        this.securityContext = context;
    }

    @Override
    protected void doExecute(Task task, QueryUserRequest request, ActionListener<QueryUserResponse> listener) {
        final Authentication authentication = securityContext.getAuthentication();
        if (authentication == null) {
            listener.onFailure(new IllegalStateException("authentication is required"));
        }

        final SearchSourceBuilder searchSourceBuilder = SearchSourceBuilder.searchSource()
            .version(false)
            .fetchSource(true)
            .trackTotalHits(true);

        if (request.getFrom() != null) {
            searchSourceBuilder.from(request.getFrom());
        }
        if (request.getSize() != null) {
            searchSourceBuilder.size(request.getSize());
        }

        final SecurityIndexBoolQueryBuilder userKeyBoolQueryBuilder = SecurityIndexBoolQueryBuilder.wrap(
            "user",
            request.getQueryBuilder(),
            fieldNameTranslator,
            authentication
        );

        searchSourceBuilder.query(userKeyBoolQueryBuilder);

        if (request.getFieldSortBuilders() != null) {
            translateFieldSortBuilders(request.getFieldSortBuilders(), searchSourceBuilder);
        }

        if (request.getSearchAfterBuilder() != null) {
            searchSourceBuilder.searchAfter(request.getSearchAfterBuilder().getSortValues());
        }

        final SearchRequest searchRequest = new SearchRequest(new String[] { SECURITY_MAIN_ALIAS }, searchSourceBuilder);
        usersStore.queryUsers(searchRequest, listener);
    }

    // package private for testing
    static void translateFieldSortBuilders(List<FieldSortBuilder> fieldSortBuilders, SearchSourceBuilder searchSourceBuilder) {
        fieldSortBuilders.forEach(fieldSortBuilder -> {
            if (fieldSortBuilder.getNestedSort() != null) {
                throw new IllegalArgumentException("nested sorting is not supported for User Key query");
            }
            if (FieldSortBuilder.DOC_FIELD_NAME.equals(fieldSortBuilder.getFieldName())) {
                searchSourceBuilder.sort(fieldSortBuilder);
            } else {
                final String translatedFieldName = fieldNameTranslator.translate(fieldSortBuilder.getFieldName());
                if (translatedFieldName.equals(fieldSortBuilder.getFieldName())) {
                    searchSourceBuilder.sort(fieldSortBuilder);
                } else {
                    final FieldSortBuilder translatedFieldSortBuilder = new FieldSortBuilder(translatedFieldName).order(
                        fieldSortBuilder.order()
                    )
                        .missing(fieldSortBuilder.missing())
                        .unmappedType(fieldSortBuilder.unmappedType())
                        .setFormat(fieldSortBuilder.getFormat());

                    if (fieldSortBuilder.sortMode() != null) {
                        translatedFieldSortBuilder.sortMode(fieldSortBuilder.sortMode());
                    }
                    if (fieldSortBuilder.getNestedSort() != null) {
                        translatedFieldSortBuilder.setNestedSort(fieldSortBuilder.getNestedSort());
                    }
                    if (fieldSortBuilder.getNumericType() != null) {
                        translatedFieldSortBuilder.setNumericType(fieldSortBuilder.getNumericType());
                    }
                    searchSourceBuilder.sort(translatedFieldSortBuilder);
                }
            }
        });
    }
}
