-------------------------- MODULE S3PolicyCondition --------------------------
(***************************************************************************)
(* Model of how one bucket policy condition is evaluated                   *)
(* (conditionOperator.evaluate in internal/backend/policy_condition.go).   *)
(*                                                                         *)
(* A condition compares the request's values for one key (absent, or      *)
(* present with a set of values) against the policy's value list with an  *)
(* operator: a comparison, optionally negated ("Not"), optionally          *)
(* "IfExists", optionally qualified "ForAllValues:" or "ForAnyValue:", or  *)
(* the presence test Null. Every comparison family (the String, Numeric, *)
(* Date, Bool, IpAddress and Arn operators) shares this composition logic *)
(* and differs only in the per-value match relation, so the model         *)
(* quantifies over                                                         *)
(* EVERY relation Match \subseteq Values \X Values: the laws below hold    *)
(* whatever the comparison is.                                             *)
(*                                                                         *)
(* Laws checked by TLC:                                                    *)
(*  - an unqualified negated operator negates its positive form;          *)
(*  - a missing key fails a positive and satisfies a negated operator;     *)
(*  - IfExists only changes the result for a missing key (to TRUE);        *)
(*  - ForAllValues over no values holds, ForAnyValue over none fails;      *)
(*  - ForAllValues:NotOp negates ForAnyValue:Op and vice versa (De Morgan);*)
(*  - for a single request value the set qualifiers change nothing;        *)
(*  - a value list is a disjunction (positive) or conjunction (negated);   *)
(*  - Null:true holds exactly when the key is missing.                     *)
(*                                                                         *)
(* internal/backend/policy_model_test.go checks the Go implementation      *)
(* against Eval below for concrete operators.                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANT Values

NonEmpty(S) == SUBSET S \ {{}}

Ops == [negated: BOOLEAN, ifExists: BOOLEAN, set: {"none", "all", "any"}]

\* Single value r against the policy list cs, honouring negation.
Single(op, m, r, cs) == (\E c \in cs : <<r, c>> \in m) # op.negated

\* Eval(op, m, present, rs, cs): the condition's result.
Eval(op, m, present, rs, cs) ==
    IF ~present \/ rs = {} THEN
        IF op.ifExists THEN TRUE
        ELSE CASE op.set = "all" -> TRUE
               [] op.set = "any" -> FALSE
               [] OTHER          -> op.negated
    ELSE CASE op.set = "all" -> \A r \in rs : Single(op, m, r, cs)
           [] op.set = "any" -> \E r \in rs : Single(op, m, r, cs)
           [] OTHER          -> (\E r \in rs, c \in cs : <<r, c>> \in m) # op.negated

EvalNull(present, cs) ==
    (\E c \in cs : (c = "true" /\ ~present) \/ (c = "false" /\ present))

VARIABLES match, present, rs, cs

vars == <<match, present, rs, cs>>

Init ==
    /\ match \in SUBSET (Values \X Values)
    /\ present \in BOOLEAN
    /\ rs \in (IF present THEN SUBSET Values ELSE {{}})
    /\ cs \in NonEmpty(Values)

Spec == Init /\ [][UNCHANGED vars]_vars

Plain(neg) == [negated |-> neg, ifExists |-> FALSE, set |-> "none"]

\* Only for the unqualified form: with a set qualifier negation swaps the
\* quantifier instead (DeMorgan below).
NegationIsComplement ==
    \A op \in Ops :
        (present /\ rs # {} /\ ~op.ifExists /\ op.set = "none") =>
            Eval([op EXCEPT !.negated = ~op.negated], match, present, rs, cs)
                = ~Eval(op, match, present, rs, cs)

MissingKey ==
    ~present =>
        /\ Eval(Plain(FALSE), match, present, rs, cs) = FALSE
        /\ Eval(Plain(TRUE), match, present, rs, cs) = TRUE

IfExistsOnlyForMissing ==
    \A op \in Ops :
        IF present /\ rs # {}
        THEN Eval([op EXCEPT !.ifExists = TRUE], match, present, rs, cs)
               = Eval([op EXCEPT !.ifExists = FALSE], match, present, rs, cs)
        ELSE Eval([op EXCEPT !.ifExists = TRUE], match, present, rs, cs)

EmptySetQualifiers ==
    rs = {} =>
        \A neg \in BOOLEAN :
            /\ Eval([negated |-> neg, ifExists |-> FALSE, set |-> "all"], match, present, rs, cs)
            /\ ~Eval([negated |-> neg, ifExists |-> FALSE, set |-> "any"], match, present, rs, cs)

DeMorgan ==
    (present /\ rs # {}) =>
        \A neg \in BOOLEAN :
            /\ Eval([negated |-> ~neg, ifExists |-> FALSE, set |-> "all"], match, present, rs, cs)
                 = ~Eval([negated |-> neg, ifExists |-> FALSE, set |-> "any"], match, present, rs, cs)
            /\ Eval([negated |-> ~neg, ifExists |-> FALSE, set |-> "any"], match, present, rs, cs)
                 = ~Eval([negated |-> neg, ifExists |-> FALSE, set |-> "all"], match, present, rs, cs)

SingletonQualifiersAgree ==
    (present /\ Cardinality(rs) = 1) =>
        \A op \in Ops :
            Eval([op EXCEPT !.set = "all"], match, present, rs, cs)
                = Eval([op EXCEPT !.set = "none"], match, present, rs, cs)
            /\ Eval([op EXCEPT !.set = "any"], match, present, rs, cs)
                = Eval([op EXCEPT !.set = "none"], match, present, rs, cs)

ValueListIsDisjunction ==
    (present /\ rs # {}) =>
        \A c1, c2 \in NonEmpty(Values) :
            /\ Eval(Plain(FALSE), match, present, rs, c1 \cup c2)
                 = (Eval(Plain(FALSE), match, present, rs, c1) \/ Eval(Plain(FALSE), match, present, rs, c2))
            /\ Eval(Plain(TRUE), match, present, rs, c1 \cup c2)
                 = (Eval(Plain(TRUE), match, present, rs, c1) /\ Eval(Plain(TRUE), match, present, rs, c2))

NullIsPresenceTest ==
    /\ EvalNull(present, {"true"}) = ~present
    /\ EvalNull(present, {"false"}) = present

=============================================================================
