/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.support;

import org.apache.lucene.search.Query;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.ExistsQueryBuilder;
import org.elasticsearch.index.query.IdsQueryBuilder;
import org.elasticsearch.index.query.MatchAllQueryBuilder;
import org.elasticsearch.index.query.PrefixQueryBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.index.query.QueryRewriteContext;
import org.elasticsearch.index.query.RangeQueryBuilder;
import org.elasticsearch.index.query.SearchExecutionContext;
import org.elasticsearch.index.query.TermQueryBuilder;
import org.elasticsearch.index.query.TermsQueryBuilder;
import org.elasticsearch.index.query.WildcardQueryBuilder;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationField;
import org.elasticsearch.xpack.security.authc.ApiKeyService;

import java.io.IOException;

public class SecurityIndexBoolQueryBuilder extends BoolQueryBuilder {
    private final SecurityIndexFieldNameTranslator fieldNameTranslator;

    private SecurityIndexBoolQueryBuilder(SecurityIndexFieldNameTranslator fieldNameTranslator) {
        this.fieldNameTranslator = fieldNameTranslator;
    }

    public static SecurityIndexBoolQueryBuilder wrap(
        String type,
        QueryBuilder queryBuilder,
        SecurityIndexFieldNameTranslator fieldNameTranslator
    ) {
        return wrap(type, queryBuilder, fieldNameTranslator, null);
    }

    public static SecurityIndexBoolQueryBuilder wrap(
        String type,
        QueryBuilder queryBuilder,
        SecurityIndexFieldNameTranslator fieldNameTranslator,
        @Nullable Authentication authentication
    ) {
        SecurityIndexBoolQueryBuilder queryBuilderWrapper = new SecurityIndexBoolQueryBuilder(fieldNameTranslator);
        if (queryBuilder != null) {
            QueryBuilder processedQuery = doProcess(fieldNameTranslator, queryBuilder);
            queryBuilderWrapper.must(processedQuery);
        }
        queryBuilderWrapper.filter(QueryBuilders.termQuery("type", type));

        if (authentication != null) {
            if (authentication.isApiKey()) {
                final String apiKeyId = (String) authentication.getAuthenticatingSubject()
                    .getMetadata()
                    .get(AuthenticationField.API_KEY_ID_KEY);
                assert apiKeyId != null : "api key id must be present in the metadata";
                queryBuilderWrapper.filter(QueryBuilders.idsQuery().addIds(apiKeyId));
            } else {
                queryBuilderWrapper.filter(
                    QueryBuilders.termQuery("creator.principal", authentication.getEffectiveSubject().getUser().principal())
                );
                final String[] realms = ApiKeyService.getOwnersRealmNames(authentication);
                final QueryBuilder realmsQuery = ApiKeyService.filterForRealmNames(realms);
                assert realmsQuery != null;
                queryBuilderWrapper.filter(realmsQuery);
            }
        }

        return queryBuilderWrapper;
    }

    private static QueryBuilder doProcess(SecurityIndexFieldNameTranslator fieldNameTranslator, QueryBuilder qb) {
        if (qb instanceof final BoolQueryBuilder query) {
            final BoolQueryBuilder newQuery = QueryBuilders.boolQuery()
                .minimumShouldMatch(query.minimumShouldMatch())
                .adjustPureNegative(query.adjustPureNegative());
            query.must().stream().map(queryBuilder -> doProcess(fieldNameTranslator, queryBuilder)).forEach(newQuery::must);
            query.should().stream().map(queryBuilder -> doProcess(fieldNameTranslator, queryBuilder)).forEach(newQuery::should);
            query.mustNot().stream().map(queryBuilder -> doProcess(fieldNameTranslator, queryBuilder)).forEach(newQuery::mustNot);
            query.filter().stream().map(queryBuilder -> doProcess(fieldNameTranslator, queryBuilder)).forEach(newQuery::filter);
            return newQuery;
        } else if (qb instanceof MatchAllQueryBuilder) {
            return qb;
        } else if (qb instanceof IdsQueryBuilder) {
            return qb;
        } else if (qb instanceof final TermQueryBuilder query) {
            final String translatedFieldName = fieldNameTranslator.translate(query.fieldName());
            return QueryBuilders.termQuery(translatedFieldName, query.value()).caseInsensitive(query.caseInsensitive());
        } else if (qb instanceof final ExistsQueryBuilder query) {
            final String translatedFieldName = fieldNameTranslator.translate(query.fieldName());
            return QueryBuilders.existsQuery(translatedFieldName);
        } else if (qb instanceof final TermsQueryBuilder query) {
            if (query.termsLookup() != null) {
                throw new IllegalArgumentException("terms query with terms lookup is not supported");
            }
            final String translatedFieldName = fieldNameTranslator.translate(query.fieldName());
            return QueryBuilders.termsQuery(translatedFieldName, query.getValues());
        } else if (qb instanceof final PrefixQueryBuilder query) {
            final String translatedFieldName = fieldNameTranslator.translate(query.fieldName());
            return QueryBuilders.prefixQuery(translatedFieldName, query.value()).caseInsensitive(query.caseInsensitive());
        } else if (qb instanceof final WildcardQueryBuilder query) {
            final String translatedFieldName = fieldNameTranslator.translate(query.fieldName());
            return QueryBuilders.wildcardQuery(translatedFieldName, query.value())
                .caseInsensitive(query.caseInsensitive())
                .rewrite(query.rewrite());
        } else if (qb instanceof final RangeQueryBuilder query) {
            final String translatedFieldName = fieldNameTranslator.translate(query.fieldName());
            if (query.relation() != null) {
                throw new IllegalArgumentException("range query with relation is not supported");
            }
            final RangeQueryBuilder newQuery = QueryBuilders.rangeQuery(translatedFieldName);
            if (query.format() != null) {
                newQuery.format(query.format());
            }
            if (query.timeZone() != null) {
                newQuery.timeZone(query.timeZone());
            }
            if (query.from() != null) {
                newQuery.from(query.from()).includeLower(query.includeLower());
            }
            if (query.to() != null) {
                newQuery.to(query.to()).includeUpper(query.includeUpper());
            }
            return newQuery.boost(query.boost());
        } else {
            throw new IllegalArgumentException("Query type [" + qb.getName() + "] is not supported for query");
        }
    }

    @Override
    protected Query doToQuery(SearchExecutionContext context) throws IOException {
        context.setAllowedFields(this::isIndexFieldNameAllowed);
        return super.doToQuery(context);
    }

    @Override
    protected QueryBuilder doRewrite(QueryRewriteContext queryRewriteContext) throws IOException {
        if (queryRewriteContext instanceof SearchExecutionContext) {
            ((SearchExecutionContext) queryRewriteContext).setAllowedFields(this::isIndexFieldNameAllowed);
        }
        return super.doRewrite(queryRewriteContext);
    }

    boolean isIndexFieldNameAllowed(String queryFieldName) {
        return queryFieldName.equals("type") || fieldNameTranslator.supportedIndexFieldName(queryFieldName);
    }
}
