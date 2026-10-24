--------------------------- MODULE S3BucketPolicy ---------------------------
(***************************************************************************)
(* Model of bucket policy evaluation (internal/backend/policy.go).         *)
(*                                                                         *)
(* A statement has an effect, a principal element (Principal or            *)
(* NotPrincipal), an action element (Action or NotAction), a resource      *)
(* element (Resource, NotResource, or none) and an abstract condition that *)
(* holds when a request flag is set, when it is clear, or always.          *)
(*                                                                         *)
(* The semantics is declarative (IAM policy evaluation logic):             *)
(*   Deny    if some applicable statement denies;                          *)
(*   Allow   otherwise, if some applicable statement allows;               *)
(*   Default otherwise (implicit deny; the caller falls back to ACLs).     *)
(* The implementation instead folds over the statement list once and      *)
(* returns as soon as an applicable Deny is found. TLC checks, for every   *)
(* policy up to MaxStmts statements and every request, that the fold      *)
(* computes the declarative result, that statement order is irrelevant,    *)
(* and the monotonicity laws policy authors rely on: adding a statement    *)
(* never lifts a Deny, adding an Allow never revokes an Allow, and adding  *)
(* a Deny never grants. Anonymous callers are matched only by "*".         *)
(*                                                                         *)
(* internal/backend/policy_model_test.go evaluates the same statement      *)
(* space with the Go implementation and compares it with this semantics.   *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Users,      \* named callers, e.g. {"u1", "u2"}
          Named,      \* users a policy may name, a subset of Users
          Actions,    \* e.g. {"get", "put"}
          Resources,  \* e.g. {"r1", "r2"}
          MaxStmts    \* longest policy explored

Anon == "anon"
Wildcard == "*"
Callers == Users \cup {Anon}

NonEmpty(S) == SUBSET S \ {{}}

Stmts ==
    [effect: {"Allow"}, pkind: {"Principal"}, pset: NonEmpty(Named \cup {Wildcard}),
     akind: {"Action", "NotAction"}, aset: NonEmpty(Actions),
     rkind: {"Resource", "NotResource"}, rset: NonEmpty(Resources),
     cond: {"none", "flag", "noflag"}]
    \cup
    [effect: {"Deny"}, pkind: {"Principal", "NotPrincipal"},
     pset: NonEmpty(Named \cup {Wildcard}),
     akind: {"Action", "NotAction"}, aset: NonEmpty(Actions),
     rkind: {"Resource", "NotResource"}, rset: NonEmpty(Resources),
     cond: {"none", "flag", "noflag"}]
    \* NotPrincipal with Allow is rejected by PutBucketPolicy.

Requests == [who: Callers, act: Actions, res: Resources, flag: BOOLEAN]

\* "*" matches every caller, anonymous included; a named user matches only
\* itself; nothing else matches an anonymous caller.
PrincipalIn(pset, who) == Wildcard \in pset \/ who \in pset

PrincipalMatches(s, q) ==
    IF s.pkind = "Principal" THEN PrincipalIn(s.pset, q.who)
    ELSE ~PrincipalIn(s.pset, q.who)

ActionMatches(s, q) ==
    IF s.akind = "Action" THEN q.act \in s.aset ELSE q.act \notin s.aset

ResourceMatches(s, q) ==
    IF s.rkind = "Resource" THEN q.res \in s.rset ELSE q.res \notin s.rset

CondHolds(s, q) ==
    CASE s.cond = "none"   -> TRUE
      [] s.cond = "flag"   -> q.flag
      [] s.cond = "noflag" -> ~q.flag

Applies(s, q) ==
    PrincipalMatches(s, q) /\ ActionMatches(s, q) /\ ResourceMatches(s, q) /\ CondHolds(s, q)

\* Declarative semantics.
Eval(p, q) ==
    IF \E i \in 1..Len(p) : p[i].effect = "Deny" /\ Applies(p[i], q) THEN "Deny"
    ELSE IF \E i \in 1..Len(p) : p[i].effect = "Allow" /\ Applies(p[i], q) THEN "Allow"
    ELSE "Default"

\* The implementation's single pass with early return on Deny.
RECURSIVE FoldFrom(_, _, _, _)
FoldFrom(p, i, allowed, q) ==
    IF i > Len(p) THEN (IF allowed THEN "Allow" ELSE "Default")
    ELSE IF Applies(p[i], q) /\ p[i].effect = "Deny" THEN "Deny"
    ELSE FoldFrom(p, i + 1, allowed \/ (Applies(p[i], q) /\ p[i].effect = "Allow"), q)

Fold(p, q) == FoldFrom(p, 1, FALSE, q)

Reverse(p) == [i \in 1..Len(p) |-> p[Len(p) + 1 - i]]

VARIABLE policy

Init == policy = <<>>

Next == Len(policy) < MaxStmts /\ \E s \in Stmts : policy' = Append(policy, s)

Spec == Init /\ [][Next]_policy

Front == SubSeq(policy, 1, Len(policy) - 1)
Last == policy[Len(policy)]

(***************************************************************************)
(* Invariants                                                              *)
(***************************************************************************)

FoldMatchesSemantics == \A q \in Requests : Fold(policy, q) = Eval(policy, q)

OrderIrrelevant == \A q \in Requests : Fold(Reverse(policy), q) = Fold(policy, q)

\* Every policy is reached by appending its last statement to Front, so
\* these cover adding any statement to any shorter policy.
DenyIsSticky ==
    Len(policy) > 0 =>
        \A q \in Requests : Eval(Front, q) = "Deny" => Eval(policy, q) = "Deny"

AllowIsMonotone ==
    (Len(policy) > 0 /\ Last.effect = "Allow") =>
        \A q \in Requests : Eval(Front, q) = "Allow" => Eval(policy, q) = "Allow"

DenyNeverGrants ==
    (Len(policy) > 0 /\ Last.effect = "Deny") =>
        \A q \in Requests : Eval(policy, q) = "Allow" => Eval(Front, q) = "Allow"

\* An anonymous caller is allowed only through a statement naming "*".
AnonymousOnlyViaWildcard ==
    \A q \in Requests :
        (q.who = Anon /\ Eval(policy, q) = "Allow") =>
            \E i \in 1..Len(policy) :
                policy[i].effect = "Allow" /\ Wildcard \in policy[i].pset /\ Applies(policy[i], q)

\* A user the policy never names is treated exactly like any other unnamed
\* user: policies cannot single out a caller they do not mention.
UnnamedUsersAreIndistinguishable ==
    \A q \in Requests :
        \A u \in Users \ Named :
            (q.who \in Users \ Named) => Eval(policy, q) = Eval(policy, [q EXCEPT !.who = u])

\* A Deny with NotPrincipal denies everyone it does not list, including
\* anonymous callers (the classic "deny all but these" pattern).
NotPrincipalDenyCoversAnonymous ==
    \A i \in 1..Len(policy) :
        LET s == policy[i] IN
        (s.effect = "Deny" /\ s.pkind = "NotPrincipal" /\ Wildcard \notin s.pset /\ s.cond = "none") =>
            \A q \in Requests :
                (q.who = Anon /\ ActionMatches(s, q) /\ ResourceMatches(s, q)) => Eval(policy, q) = "Deny"

\* NotAction S applies exactly to the actions Action (Actions \ S) names.
NotActionIsComplement ==
    \A i \in 1..Len(policy) :
        LET s == policy[i] IN
        (s.akind = "NotAction" /\ s.aset # Actions) =>
            \A q \in Requests :
                Applies(s, q) = Applies([s EXCEPT !.akind = "Action", !.aset = Actions \ s.aset], q)

NotResourceIsComplement ==
    \A i \in 1..Len(policy) :
        LET s == policy[i] IN
        (s.rkind = "NotResource" /\ s.rset # Resources) =>
            \A q \in Requests :
                Applies(s, q) = Applies([s EXCEPT !.rkind = "Resource", !.rset = Resources \ s.rset], q)

=============================================================================
