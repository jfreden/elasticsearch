/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.compute.aggregation;

import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.IntBlock;
import org.elasticsearch.compute.data.LongBlock;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.LongIntBlockSourceOperator;
import org.elasticsearch.compute.operator.SourceOperator;
import org.elasticsearch.core.Tuple;

import java.util.List;
import java.util.stream.LongStream;

import static org.hamcrest.Matchers.equalTo;

public class SumIntGroupingAggregatorFunctionTests extends GroupingAggregatorFunctionTestCase {
    @Override
    protected GroupingAggregatorFunction.Factory aggregatorFunction() {
        return GroupingAggregatorFunction.SUM_INTS;
    }

    @Override
    protected String expectedDescriptionOfAggregator() {
        return "sum of ints";
    }

    @Override
    protected SourceOperator simpleInput(int size) {
        int max = between(1, (int) Math.min(Integer.MAX_VALUE, Long.MAX_VALUE / size));
        return new LongIntBlockSourceOperator(
            LongStream.range(0, size).mapToObj(l -> Tuple.tuple(randomLongBetween(0, 4), between(-max, max)))
        );
    }

    @Override
    protected void assertSimpleGroup(List<Page> input, Block result, int position, long group) {
        long[] sum = new long[] { 0 };
        forEachGroupAndValue(input, (groups, groupOffset, values, valueOffset) -> {
            if (groups.getLong(groupOffset) == group) {
                sum[0] = Math.addExact(sum[0], (long) ((IntBlock) values).getInt(valueOffset));
            }
        });
        assertThat(((LongBlock) result).getLong(position), equalTo(sum[0]));
    }
}
