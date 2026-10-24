package backend

// evaluateCondition evaluates one condition value against the request, the
// single-value form of evaluateConditionValues.
func evaluateCondition(operator, condKey, condValue string, ctx PolicyEvalContext) bool {
	return evaluateConditionValues(operator, condKey, PolicyStringOrSlice{condValue}, ctx)
}

// getConditionKeyValue returns the first request value for a condition key,
// or "" when the key is absent.
func getConditionKeyValue(condKey string, ctx PolicyEvalContext) string {
	values, ok := lookupConditionKey(condKey, ctx)
	if !ok || len(values) == 0 {
		return ""
	}
	return values[0]
}
