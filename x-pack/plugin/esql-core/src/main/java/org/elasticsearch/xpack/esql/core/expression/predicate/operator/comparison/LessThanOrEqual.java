/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.esql.core.expression.predicate.operator.comparison;

import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.xpack.esql.core.expression.Expression;
import org.elasticsearch.xpack.esql.core.expression.predicate.Negatable;
import org.elasticsearch.xpack.esql.core.tree.NodeInfo;
import org.elasticsearch.xpack.esql.core.tree.Source;

import java.io.IOException;
import java.time.ZoneId;

public class LessThanOrEqual extends BinaryComparison implements Negatable<BinaryComparison> {

    public LessThanOrEqual(Source source, Expression left, Expression right, ZoneId zoneId) {
        super(source, left, right, BinaryComparisonOperation.LTE, zoneId);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getWriteableName() {
        throw new UnsupportedOperationException();
    }

    @Override
    protected NodeInfo<LessThanOrEqual> info() {
        return NodeInfo.create(this, LessThanOrEqual::new, left(), right(), zoneId());
    }

    @Override
    protected LessThanOrEqual replaceChildren(Expression newLeft, Expression newRight) {
        return new LessThanOrEqual(source(), newLeft, newRight, zoneId());
    }

    @Override
    public GreaterThanOrEqual swapLeftAndRight() {
        return new GreaterThanOrEqual(source(), right(), left(), zoneId());
    }

    @Override
    public GreaterThan negate() {
        return new GreaterThan(source(), left(), right(), zoneId());
    }

    @Override
    public BinaryComparison reverse() {
        return new GreaterThanOrEqual(source(), left(), right(), zoneId());
    }
}
