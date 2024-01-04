/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.action.user;

import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.support.TransportAction;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xcontent.ToXContentObject;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xpack.core.security.user.User;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * Response for query Users. <br>
 * The result contains information about the Users that were found.
 */
public final class QueryUserResponse extends ActionResponse implements ToXContentObject {

    private final long total;
    private final Item[] items;

    public QueryUserResponse(long total, Collection<Item> items) {
        this.total = total;
        Objects.requireNonNull(items, "items must be provided");
        this.items = items.toArray(new Item[0]);
    }

    public static QueryUserResponse emptyResponse() {
        return new QueryUserResponse(0, Collections.emptyList());
    }

    public long getTotal() {
        return total;
    }

    public Item[] getItems() {
        return items;
    }

    public int getCount() {
        return items.length;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field("total", total).field("count", items.length).array("users", (Object[]) items);
        return builder.endObject();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        QueryUserResponse that = (QueryUserResponse) o;
        return total == that.total && Arrays.equals(items, that.items);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(total);
        result = 31 * result + Arrays.hashCode(items);
        return result;
    }

    @Override
    public String toString() {
        return "QueryUsersResponse{" + "total=" + total + ", items=" + Arrays.toString(items) + '}';
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        TransportAction.localOnly();
    }

    public static class Item implements ToXContentObject {
        private final User user;
        @Nullable
        private final Object[] sortValues;

        public Item(User user, @Nullable Object[] sortValues) {
            this.user = user;
            this.sortValues = sortValues;
        }

        public User getUser() {
            return user;
        }

        public Object[] getSortValues() {
            return sortValues;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            user.innerToXContent(builder);
            if (sortValues != null && sortValues.length > 0) {
                builder.array("_sort", sortValues);
            }
            builder.endObject();
            return builder;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Item item = (Item) o;
            return Objects.equals(this.user, item.user) && Arrays.equals(sortValues, item.sortValues);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(user);
            result = 31 * result + Arrays.hashCode(sortValues);
            return result;
        }

        @Override
        public String toString() {
            return "Item{" + "user=" + user + ", sortValues=" + Arrays.toString(sortValues) + '}';
        }
    }
}
