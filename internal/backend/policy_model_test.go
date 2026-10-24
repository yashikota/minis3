package backend

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"slices"
	"testing"
)

// This file checks the policy evaluator against the semantics model-checked
// in formal/tla/S3BucketPolicy.tla and formal/tla/S3PolicyCondition.tla. The
// statement space, request space and Eval functions below transcribe the TLA+
// definitions; the tests enumerate the same spaces TLC explores.

type modelStmt struct {
	effect string // "Allow" | "Deny"
	notP   bool
	pset   []string // subset of {"u1", "*"}
	notA   bool
	aset   []string // subset of modelActions
	notR   bool
	rset   []string // subset of modelResources
	cond   string   // "none" | "flag" | "noflag"
}

type modelRequest struct {
	who  string // "u1" | "u2" | "u3" | "anon"
	act  string
	res  string
	flag bool
}

var (
	modelCallers = []string{"u1", "u2", "u3", "anon"}
	// The model's users are three static identities; only u1 is ever named.
	modelAccessKeys = map[string]string{
		"u1": "minis3-alt-access-key",
		"u2": "tenant-access-key",
		"u3": "minis3-access-key",
	}
	modelActionNames   = map[string]string{"get": "s3:GetObject", "put": "s3:PutObject"}
	modelResourceNames = map[string]string{
		"r1": "arn:aws:s3:::model-bucket/r1",
		"r2": "arn:aws:s3:::model-bucket/r2",
	}
)

func nonEmptySubsets(items []string) [][]string {
	var out [][]string
	for mask := 1; mask < 1<<len(items); mask++ {
		var s []string
		for i, item := range items {
			if mask&(1<<i) != 0 {
				s = append(s, item)
			}
		}
		out = append(out, s)
	}
	return out
}

// modelStatements enumerates Stmts from S3BucketPolicy.tla.
func modelStatements(actions, resources []string) []modelStmt {
	var out []modelStmt
	for _, effect := range []string{"Allow", "Deny"} {
		for _, notP := range []bool{false, true} {
			if notP && effect == "Allow" {
				continue
			}
			for _, pset := range nonEmptySubsets([]string{"u1", "*"}) {
				for _, notA := range []bool{false, true} {
					for _, aset := range nonEmptySubsets(actions) {
						for _, notR := range []bool{false, true} {
							for _, rset := range nonEmptySubsets(resources) {
								for _, cond := range []string{"none", "flag", "noflag"} {
									out = append(out, modelStmt{
										effect, notP, pset, notA, aset, notR, rset, cond,
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

func modelRequests(actions, resources []string) []modelRequest {
	var out []modelRequest
	for _, who := range modelCallers {
		for _, act := range actions {
			for _, res := range resources {
				for _, flag := range []bool{false, true} {
					out = append(out, modelRequest{who, act, res, flag})
				}
			}
		}
	}
	return out
}

func (s modelStmt) applies(q modelRequest) bool {
	inP := slices.Contains(s.pset, "*") || slices.Contains(s.pset, q.who)
	if s.notP {
		inP = !inP
	}
	inA := slices.Contains(s.aset, q.act) != s.notA
	inR := slices.Contains(s.rset, q.res) != s.notR
	cond := s.cond == "none" || (s.cond == "flag") == q.flag
	return inP && inA && inR && cond
}

// modelEval is Eval from S3BucketPolicy.tla.
func modelEval(p []modelStmt, q modelRequest) PolicyEffect {
	allow := false
	for _, s := range p {
		if s.applies(q) {
			if s.effect == "Deny" {
				return PolicyEffectDeny
			}
			allow = true
		}
	}
	if allow {
		return PolicyEffectAllow
	}
	return PolicyEffectDefault
}

func (s modelStmt) toJSON() map[string]any {
	principals := make([]any, 0, len(s.pset))
	for _, p := range s.pset {
		if p == "*" {
			principals = append(principals, "*")
		} else {
			principals = append(principals, PrincipalForAccessKey(modelAccessKeys[p]).ARN)
		}
	}
	actions := make([]any, 0, len(s.aset))
	for _, a := range s.aset {
		actions = append(actions, modelActionNames[a])
	}
	resources := make([]any, 0, len(s.rset))
	for _, r := range s.rset {
		resources = append(resources, modelResourceNames[r])
	}
	stmt := map[string]any{"Effect": s.effect}
	pKey, aKey, rKey := "Principal", "Action", "Resource"
	if s.notP {
		pKey = "NotPrincipal"
	}
	if s.notA {
		aKey = "NotAction"
	}
	if s.notR {
		rKey = "NotResource"
	}
	stmt[pKey] = map[string]any{"AWS": principals}
	stmt[aKey] = actions
	stmt[rKey] = resources
	switch s.cond {
	case "flag":
		stmt["Condition"] = map[string]any{"Bool": map[string]any{"aws:SecureTransport": true}}
	case "noflag":
		stmt["Condition"] = map[string]any{"Bool": map[string]any{"aws:SecureTransport": "false"}}
	}
	return stmt
}

func modelPolicyJSON(t testing.TB, p []modelStmt) string {
	t.Helper()
	statements := make([]any, 0, len(p))
	for _, s := range p {
		statements = append(statements, s.toJSON())
	}
	raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return string(raw)
}

func (q modelRequest) context() PolicyEvalContext {
	ctx := PolicyEvalContext{
		Action:        modelActionNames[q.act],
		Resource:      modelResourceNames[q.res],
		ConditionKeys: map[string][]string{"aws:securetransport": {fmt.Sprint(q.flag)}},
	}
	if q.who == "anon" {
		ctx.IsAnonymous = true
	} else {
		ctx.AccessKey = modelAccessKeys[q.who]
	}
	return ctx
}

// TestBucketPolicyModelSingleStatements runs every single-statement policy of
// S3BucketPolicy.cfg through PutBucketPolicy validation and the evaluator.
func TestBucketPolicyModelSingleStatements(t *testing.T) {
	t.Parallel()
	actions, resources := []string{"get", "put"}, []string{"r1", "r2"}
	stmts := modelStatements(actions, resources)
	if len(stmts) != 972 {
		t.Fatalf("statement space has %d statements, the TLA+ model has 972", len(stmts))
	}
	requests := modelRequests(actions, resources)
	for _, s := range stmts {
		policy := modelPolicyJSON(t, []modelStmt{s})
		if err := ValidateBucketPolicy(policy, "model-bucket"); err != nil {
			t.Fatalf("model policy rejected: %v\n%s", err, policy)
		}
		for _, q := range requests {
			want := modelEval([]modelStmt{s}, q)
			if got := EvaluateBucketPolicyAccess(policy, q.context()); got != want {
				t.Fatalf("Evaluate = %v, model = %v\nrequest %+v\npolicy %s", got, want, q, policy)
			}
		}
	}
}

// TestBucketPolicyModelPairs covers every two-statement policy of
// S3BucketPolicyPairs.cfg, in both orders.
func TestBucketPolicyModelPairs(t *testing.T) {
	t.Parallel()
	actions, resources := []string{"get", "put"}, []string{"r1"}
	stmts := modelStatements(actions, resources)
	if len(stmts) != 324 {
		t.Fatalf("statement space has %d statements, the TLA+ model has 324", len(stmts))
	}
	parsed := make([]PolicyStatement, len(stmts))
	for i, s := range stmts {
		policy := modelPolicyJSON(t, []modelStmt{s})
		p, ok := parseBucketPolicy(policy)
		if !ok {
			t.Fatalf("model policy does not parse: %s", policy)
		}
		parsed[i] = p.Statement[0]
	}
	requests := modelRequests(actions, resources)
	contexts := make([]PolicyEvalContext, len(requests))
	for i, q := range requests {
		contexts[i] = q.context()
		contexts[i].Principal = resolvePrincipal(contexts[i])
	}
	for i := range stmts {
		for j := range stmts {
			policy := BucketPolicy{Statement: PolicyStatementList{parsed[i], parsed[j]}}
			model := []modelStmt{stmts[i], stmts[j]}
			for k, q := range requests {
				want := modelEval(model, q)
				if got := policy.evaluate(contexts[k]); got != want {
					t.Fatalf("Evaluate = %v, model = %v\nrequest %+v\nstatements %+v",
						got, want, q, model)
				}
			}
		}
	}
}

// TestBucketPolicyModelRandomLongPolicies samples longer policies, which TLC
// does not enumerate.
func TestBucketPolicyModelRandomLongPolicies(t *testing.T) {
	t.Parallel()
	actions, resources := []string{"get", "put"}, []string{"r1", "r2"}
	stmts := modelStatements(actions, resources)
	requests := modelRequests(actions, resources)
	rng := rand.New(rand.NewSource(20261024))
	for iter := 0; iter < 1500; iter++ {
		n := 3 + rng.Intn(4)
		p := make([]modelStmt, n)
		for i := range p {
			p[i] = stmts[rng.Intn(len(stmts))]
		}
		policy := modelPolicyJSON(t, p)
		if err := ValidateBucketPolicy(policy, "model-bucket"); err != nil {
			t.Fatalf("model policy rejected: %v", err)
		}
		parsed, ok := parseBucketPolicy(policy)
		if !ok {
			t.Fatalf("model policy does not parse: %s", policy)
		}
		reversed := BucketPolicy{Statement: slices.Clone(parsed.Statement)}
		slices.Reverse(reversed.Statement)
		for _, q := range requests {
			want := modelEval(p, q)
			if got := parsed.evaluate(q.context()); got != want {
				t.Fatalf("Evaluate = %v, model = %v\nrequest %+v\npolicy %s", got, want, q, policy)
			}
			if got := reversed.evaluate(q.context()); got != want {
				t.Fatalf("statement order changed the result: %v vs %v", got, want)
			}
		}
	}
}

// modelConditionEval is Eval from S3PolicyCondition.tla.
func modelConditionEval(
	negated, ifExists bool,
	set int,
	match func(r, c string) bool,
	present bool,
	rs, cs []string,
) bool {
	if !present || len(rs) == 0 {
		if ifExists {
			return true
		}
		switch set {
		case condSetForAllValues:
			return true
		case condSetForAnyValue:
			return false
		}
		return negated
	}
	single := func(r string) bool {
		return slices.ContainsFunc(cs, func(c string) bool { return match(r, c) }) != negated
	}
	switch set {
	case condSetForAllValues:
		for _, r := range rs {
			if !single(r) {
				return false
			}
		}
		return true
	case condSetForAnyValue:
		return slices.ContainsFunc(rs, single)
	default:
		any := false
		for _, r := range rs {
			for _, c := range cs {
				any = any || match(r, c)
			}
		}
		return any != negated
	}
}

func allSubsets(items []string) [][]string {
	out := [][]string{{}}
	return append(out, nonEmptySubsets(items)...)
}

// TestPolicyConditionModel compares every operator form, built from its
// textual name exactly as a policy spells it, with the condition model, for
// every presence/value-set combination over three values.
func TestPolicyConditionModel(t *testing.T) {
	values := []string{"a", "b", "c"}
	// Policy values for the Like family include patterns.
	likeValues := []string{"a", "?", "*"}
	families := []struct {
		positive, negative string
		kind               conditionKind
		condValues         []string
	}{
		{"StringEquals", "StringNotEquals", condString, values},
		{
			"StringEqualsIgnoreCase",
			"StringNotEqualsIgnoreCase",
			condStringIgnoreCase,
			[]string{"A", "b", "C"},
		},
		{"StringLike", "StringNotLike", condStringLike, likeValues},
		{
			"ArnLike",
			"ArnNotLike",
			condArn,
			[]string{"arn:aws:s3:::a", "arn:aws:s3:::*", "arn:*:s3:::b"},
		},
	}
	arnValues := []string{"arn:aws:s3:::a", "arn:aws:s3:::b", "arn:aws:iam::1:root"}
	for _, fam := range families {
		requestValues := values
		if fam.kind == condArn {
			requestValues = arnValues
		}
		match := func(r, c string) bool { return conditionValueMatches(fam.kind, r, c) }
		for _, negated := range []bool{false, true} {
			for _, ifExists := range []bool{false, true} {
				for _, set := range []int{condSetNone, condSetForAllValues, condSetForAnyValue} {
					name := fam.positive
					if negated {
						name = fam.negative
					}
					if ifExists {
						name += "IfExists"
					}
					switch set {
					case condSetForAllValues:
						name = "ForAllValues:" + name
					case condSetForAnyValue:
						name = "ForAnyValue:" + name
					}
					op, ok := parseConditionOperator(name)
					if !ok || op.negated != negated || op.ifExists != ifExists || op.set != set {
						t.Fatalf("parseConditionOperator(%q) = %+v, %v", name, op, ok)
					}
					for _, present := range []bool{false, true} {
						requestSets := [][]string{{}}
						if present {
							requestSets = allSubsets(requestValues)
						}
						for _, rs := range requestSets {
							for _, cs := range nonEmptySubsets(fam.condValues) {
								want := modelConditionEval(
									negated,
									ifExists,
									set,
									match,
									present,
									rs,
									cs,
								)
								if got := op.evaluate(rs, present, cs); got != want {
									t.Fatalf(
										"%s(present=%v, request=%q, policy=%q) = %v, model = %v",
										name,
										present,
										rs,
										cs,
										got,
										want,
									)
								}
								// The same through the evaluator's key lookup.
								ctx := PolicyEvalContext{Action: "s3:GetObject"}
								if present {
									ctx.ConditionKeys = map[string][]string{"aws:testkey": rs}
								}
								got := evaluateConditionValues(name, "aws:TestKey", cs, ctx)
								if got != want {
									t.Fatalf(
										"evaluateConditionValues(%s) = %v, model = %v",
										name,
										got,
										want,
									)
								}
							}
						}
					}
				}
			}
		}
	}

	nullOp, ok := parseConditionOperator("Null")
	if !ok {
		t.Fatal("Null operator not recognised")
	}
	for _, present := range []bool{false, true} {
		if got := nullOp.evaluate([]string{"x"}, present, []string{"true"}); got != !present {
			t.Fatalf("Null:true with present=%v = %v", present, got)
		}
		if got := nullOp.evaluate([]string{"x"}, present, []string{"false"}); got != present {
			t.Fatalf("Null:false with present=%v = %v", present, got)
		}
	}
	for _, invalid := range []string{"NullIfExists", "ForAnyValue:Null", "Foo", "stringequals", "ForAllValues:"} {
		if _, ok := parseConditionOperator(invalid); ok {
			t.Fatalf("parseConditionOperator(%q) accepted an invalid operator", invalid)
		}
	}
}
