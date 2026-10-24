--------------------------- MODULE S3Authorization ---------------------------
(***************************************************************************)
(* Model of the authorization decision for one S3 request                  *)
(* (Handler.checkAccess in internal/handler/handler.go), which the router  *)
(* applies to every operation's IAM action.                                *)
(*                                                                         *)
(* A request is described by:                                              *)
(*  - caller: the bucket owner, another user, or an anonymous caller;      *)
(*  - kind: what the action is -                                           *)
(*      "bucketAcl"    a bucket action an ACL can grant (s3:ListBucket),   *)
(*      "bucketConfig" a configuration action no ACL grants                *)
(*                     (s3:PutBucketTagging),                              *)
(*      "policyMgmt"   s3:GetBucketPolicy and the other policy actions,    *)
(*      "object"       an object action granted by the object ACL          *)
(*                     (s3:GetObject),                                     *)
(*      "objectAcp"    s3:GetObjectAcl, which even the bucket owner needs  *)
(*                     the object ACL for;                                 *)
(*  - policy: the bucket policy's verdict for this request - no statement  *)
(*    applies, an Allow applies, a Deny applies, or an Allow matches but   *)
(*    its condition fails;                                                 *)
(*  - publicPolicy: the bucket policy is public;                           *)
(*  - grant: the ACL grants the caller the permission directly, through a  *)
(*    public group (AllUsers), or not at all;                              *)
(*  - the bucket's settings: ObjectOwnership BucketOwnerEnforced, the      *)
(*    IgnorePublicAcls and RestrictPublicBuckets blocks, and whether the   *)
(*    policy was set with ConfirmRemoveSelfBucketAccess (denySelf).        *)
(*                                                                         *)
(* Decide is the implementation's sequence of checks. TLC checks for      *)
(* every request that it equals the declarative rule Allowed and that the *)
(* properties below hold. internal/handler/authorization_model_test.go    *)
(* builds every one of these requests against a real bucket and compares *)
(* checkAccess with Decide.                                                *)
(***************************************************************************)

Callers  == {"owner", "other", "anon"}
Kinds    == {"bucketAcl", "bucketConfig", "policyMgmt", "object", "objectAcp"}
Verdicts == {"none", "allow", "deny", "allowCondFail"}
Grants   == {"none", "direct", "public"}

Requests == [caller: Callers, kind: Kinds, policy: Verdicts,
             publicPolicy: BOOLEAN, grant: Grants, ignorePublicAcls: BOOLEAN,
             enforced: BOOLEAN, restrictPublic: BOOLEAN, denySelf: BOOLEAN]

\* Shapes that cannot occur: an anonymous caller is matched only by
\* Principal "*", so an Allow that applies to it makes the policy public,
\* and an anonymous caller can be granted only through AllUsers.
Consistent(r) ==
    /\ r.caller = "anon" /\ r.policy \in {"allow", "allowCondFail"} => r.publicPolicy
    /\ r.caller = "anon" => r.grant # "direct"

Valid == {r \in Requests : Consistent(r)}

AclGrantable == {"bucketAcl", "object", "objectAcp"}

EffectiveGrant(r) ==
    \/ r.grant = "direct"
    \/ r.grant = "public" /\ ~r.ignorePublicAcls

OwnerExempt(r) == r.caller = "owner" /\ r.kind = "policyMgmt" /\ ~r.denySelf

\* checkAccess, step by step.
Decide(r) ==
    IF r.policy = "deny" /\ ~OwnerExempt(r) THEN FALSE
    ELSE IF r.restrictPublic /\ r.publicPolicy /\ r.caller # "owner" THEN FALSE
    ELSE IF r.policy = "allow" THEN TRUE
    ELSE IF r.caller = "owner" /\ r.kind # "objectAcp" THEN TRUE
    ELSE IF r.policy = "allowCondFail" THEN FALSE
    ELSE IF r.enforced THEN FALSE
    ELSE IF r.kind \notin AclGrantable THEN FALSE
    ELSE EffectiveGrant(r)

\* The same decision as one rule: no explicit Deny, no public-bucket
\* restriction, and a grant from the policy, ownership or (when ACLs are
\* in force and no conditional Allow matched) an ACL.
Allowed(r) ==
    /\ ~(r.policy = "deny" /\ ~OwnerExempt(r))
    /\ ~(r.restrictPublic /\ r.publicPolicy /\ r.caller # "owner")
    /\ \/ r.policy = "allow"
       \/ r.caller = "owner" /\ r.kind # "objectAcp"
       \/ /\ r.policy # "allowCondFail"
          /\ ~r.enforced
          /\ r.kind \in AclGrantable
          /\ EffectiveGrant(r)

With(r, field, value) == [r EXCEPT ![field] = value]

\* Each request is its own initial state; the properties below are checked
\* for every one of them.
VARIABLE req
vars == <<req>>

DecideMatchesSemantics == LET r == req IN
        Decide(r) = Allowed(r)

\* An explicit Deny always wins, except that the owner keeps managing the
\* policy unless it confirmed removing its own access.
ExplicitDenyWins ==
    LET r == req IN
        r.policy = "deny" => (Decide(r) <=> OwnerExempt(r))

OwnerCannotLockItselfOutByAccident ==
    LET r == req IN
        OwnerExempt(r) => Decide(r)

\* With BucketOwnerEnforced, ACLs play no part.
EnforcedIgnoresAcls ==
    LET r == req IN
        r.enforced =>
        \A g \in Grants : Consistent(With(r, "grant", g)) =>
            Decide(With(r, "grant", g)) = Decide(r)

\* IgnorePublicAcls makes a public grant worth nothing.
IgnorePublicAclsDropsPublicGrants ==
    LET r == req IN
        r.ignorePublicAcls /\ r.grant = "public" =>
        Decide(r) = Decide(With(r, "grant", "none"))

\* RestrictPublicBuckets: with a public policy only the owner gets in.
RestrictPublicBucketsAdmitsOnlyOwner ==
    LET r == req IN
        r.restrictPublic /\ r.publicPolicy /\ Decide(r) => r.caller = "owner"

\* A matching Allow whose condition fails does not fall back to ACLs.
FailedConditionalAllowDenies ==
    LET r == req IN
        r.policy = "allowCondFail" /\ r.caller # "owner" => ~Decide(r)

\* Configuration and policy actions need ownership or an Allow.
ConfigNeedsOwnerOrPolicy ==
    LET r == req IN
        r.kind \in {"bucketConfig", "policyMgmt"} /\ Decide(r) =>
        r.caller = "owner" \/ r.policy = "allow"

\* Anyone else needs an Allow or an ACL grant in force.
OthersNeedAllowOrGrant ==
    LET r == req IN
        r.caller # "owner" /\ Decide(r) =>
        r.policy = "allow" \/ (EffectiveGrant(r) /\ ~r.enforced)

\* More grants or an Allow in place of nothing never take access away.
GrantsAreMonotone ==
    LET r == req IN
        r.grant = "none" /\ Decide(r) =>
        Decide(With(r, "grant", "public")) /\
        (r.caller # "anon" => Decide(With(r, "grant", "direct")))

AllowIsMonotone ==
    LET r == req IN
        r.policy = "none" /\ Decide(r) =>
        (Consistent(With(r, "policy", "allow")) => Decide(With(r, "policy", "allow")))

\* The bucket's public access settings only ever restrict.
BlocksOnlyRestrict ==
    LET r == req IN
        \A f \in {"ignorePublicAcls", "restrictPublic", "enforced"} :
        r[f] /\ Decide(r) => Decide(With(r, f, FALSE))

Init == req \in Valid
Spec == Init /\ [][UNCHANGED vars]_vars
=============================================================================
