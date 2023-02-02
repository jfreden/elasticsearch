/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.compute.aggregation;

import org.elasticsearch.compute.data.Block;
import org.elasticsearch.compute.data.IntBlock;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.operator.LongIntBlockSourceOperator;
import org.elasticsearch.compute.operator.SourceOperator;
import org.elasticsearch.core.Tuple;

import java.util.List;
import java.util.stream.LongStream;

import static org.hamcrest.Matchers.equalTo;

public class MinIntGroupingAggregatorFunctionTests extends GroupingAggregatorFunctionTestCase {
    @Override
    protected GroupingAggregatorFunction.Factory aggregatorFunction() {
        return GroupingAggregatorFunction.MIN_INTS;
    }

    @Override
    protected String expectedDescriptionOfAggregator() {
        return "min of ints";
    }

    @Override
    protected SourceOperator simpleInput(int size) {
        return new LongIntBlockSourceOperator(LongStream.range(0, size).mapToObj(l -> Tuple.tuple(randomLongBetween(0, 4), randomInt())));
    }

    @Override
    public void assertSimpleGroup(List<Page> input, Block result, int position, long group) {
        int[] min = new int[] { Integer.MAX_VALUE };
        forEachGroupAndValue(input, (groups, groupOffset, values, valueOffset) -> {
            if (groups.getLong(groupOffset) == group) {
                min[0] = Math.min(min[0], ((IntBlock) values).getInt(valueOffset));
            }
        });
        assertThat(((IntBlock) result).getInt(position), equalTo(min[0]));
    }
}
