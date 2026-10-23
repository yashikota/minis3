--------------------------- MODULE S3Versioning ---------------------------
(***************************************************************************)
(* Abstract model of S3 object versioning in one bucket, as implemented by *)
(* minis3 (internal/backend/object.go, bucket.go, objectlock.go).          *)
(*                                                                         *)
(* Each key maps to a stack of versions, newest first. A version is a      *)
(* record [id, dm, hold]: its version ID ("null" or a fresh ID), whether   *)
(* it is a delete marker, and whether a legal hold is ON.                  *)
(*                                                                         *)
(* The same actions are transliterated into versioningModel in             *)
(* internal/backend/model_versioning_test.go, which runs them in lockstep  *)
(* with the real backend. TLC checks the invariants and temporal           *)
(* properties below over every reachable state for small bounds.           *)
(*                                                                         *)
(* AWS references:                                                         *)
(*  - Versioning states: a bucket is unversioned, enabled or suspended;    *)
(*    once versioned it can never return to unversioned.                   *)
(*  - Enabled: PUT and DELETE add versions with fresh IDs (DELETE adds a   *)
(*    delete marker).                                                      *)
(*  - Suspended / unversioned: PUT and DELETE replace the null version     *)
(*    (DELETE writes a null delete marker when suspended; physically       *)
(*    deletes when unversioned).                                           *)
(*  - DELETE with a version ID permanently removes that version, unless    *)
(*    Object Lock protects it.                                             *)
(*  - Object Lock requires versioning Enabled and versioning can no        *)
(*    longer be suspended afterwards.                                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Keys,        \* object keys, e.g. {"k1", "k2"}
          MaxIds       \* bound on fresh version IDs issued (state space)

Null == 0                       \* the "null" version ID
Ids  == 1..MaxIds               \* fresh version IDs
States == {"Unset", "Enabled", "Suspended"}

Version == [id: {Null} \cup Ids, dm: BOOLEAN, hold: BOOLEAN]

VARIABLES versioning,  \* bucket versioning state
          lock,        \* Object Lock enabled on the bucket
          objects,     \* objects[k] : Seq(Version), newest first
          nextId       \* next fresh version ID

vars == <<versioning, lock, objects, nextId>>

----------------------------------------------------------------------------
(* Helpers *)

RemoveNull(s) == SelectSeq(s, LAMBDA v : v.id # Null)

RemoveAt(s, i) == SubSeq(s, 1, i - 1) \o SubSeq(s, i + 1, Len(s))

\* The version ID written by PUT/DELETE in the current versioning state.
NewId == IF versioning = "Enabled" THEN nextId ELSE Null

\* Write a new version on top of k (TLA+ form of addVersionToObject and
\* createDeleteMarkerUnlocked).
Write(k, isDM) ==
    LET v    == [id |-> NewId, dm |-> isDM, hold |-> FALSE]
        base == IF versioning = "Enabled" THEN objects[k] ELSE RemoveNull(objects[k])
    IN  /\ objects' = [objects EXCEPT ![k] = <<v>> \o base]
        /\ nextId' = IF versioning = "Enabled" THEN nextId + 1 ELSE nextId

CanIssue == versioning = "Enabled" => nextId <= MaxIds

----------------------------------------------------------------------------
(* Actions *)

Init == /\ versioning = "Unset"
        /\ lock = FALSE
        /\ objects = [k \in Keys |-> <<>>]
        /\ nextId = 1

Put(k) == /\ CanIssue
          /\ Write(k, FALSE)
          /\ UNCHANGED <<versioning, lock>>

\* DELETE without a version ID.
Delete(k) ==
    \/ /\ versioning = "Unset"
       /\ objects' = [objects EXCEPT ![k] = <<>>]
       /\ UNCHANGED <<versioning, lock, nextId>>
    \/ /\ versioning # "Unset"
       /\ CanIssue
       /\ Write(k, TRUE)
       /\ UNCHANGED <<versioning, lock>>

\* DELETE with a version ID: rejected (no change) for a held version.
DeleteVersion(k, i) ==
    /\ i \in 1..Len(objects[k])
    /\ ~(objects[k][i].hold /\ ~objects[k][i].dm)
    /\ objects' = [objects EXCEPT ![k] = RemoveAt(@, i)]
    /\ UNCHANGED <<versioning, lock, nextId>>

\* PutBucketVersioning. "Unset" models a request without a Status element:
\* it leaves the state unchanged. Suspending is rejected under Object Lock.
SetVersioning(s) ==
    /\ s \in States
    /\ ~(lock /\ s = "Suspended")
    /\ versioning' = IF s = "Unset" THEN versioning ELSE s
    /\ UNCHANGED <<lock, objects, nextId>>

\* PutObjectLockConfiguration with a valid configuration.
EnableLock ==
    /\ versioning = "Enabled"
    /\ lock' = TRUE
    /\ UNCHANGED <<versioning, objects, nextId>>

\* PutObjectLegalHold on a (non delete marker) version.
SetHold(k, i, on) ==
    /\ lock
    /\ i \in 1..Len(objects[k])
    /\ ~objects[k][i].dm
    /\ objects' = [objects EXCEPT ![k][i].hold = on]
    /\ UNCHANGED <<versioning, lock, nextId>>

Next ==
    \/ \E k \in Keys : Put(k) \/ Delete(k)
    \/ \E k \in Keys, i \in 1..(MaxIds + 1) : DeleteVersion(k, i)
    \/ \E s \in States : SetVersioning(s)
    \/ EnableLock
    \/ \E k \in Keys, i \in 1..(MaxIds + 1), on \in BOOLEAN : SetHold(k, i, on)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Observations (what GET and the list APIs return) *)

\* GET without a version ID succeeds iff the current version is live.
Visible(k) == Len(objects[k]) > 0 /\ ~objects[k][1].dm

IdsOf(k) == {objects[k][i].id : i \in 1..Len(objects[k])}

----------------------------------------------------------------------------
(* Safety properties *)

TypeOK ==
    /\ versioning \in States
    /\ lock \in BOOLEAN
    /\ \A k \in Keys : objects[k] \in Seq(Version)
    /\ nextId \in 1..(MaxIds + 1)

\* At most one null version per key.
NullUnique ==
    \A k \in Keys : Cardinality({i \in 1..Len(objects[k]) : objects[k][i].id = Null}) <= 1

\* Version IDs are unique within a key, and fresh IDs across the bucket.
IdsUnique ==
    /\ \A k \in Keys : Cardinality(IdsOf(k)) = Len(objects[k])
    /\ \A k1, k2 \in Keys : k1 # k2 => (IdsOf(k1) \cap IdsOf(k2)) \subseteq {Null}

\* An unversioned bucket holds only null versions and no delete markers.
UnversionedOnlyNull ==
    versioning = "Unset" =>
        \A k \in Keys : \A i \in 1..Len(objects[k]) :
            objects[k][i].id = Null /\ ~objects[k][i].dm

\* Object Lock implies versioning stays Enabled.
LockImpliesEnabled == lock => versioning = "Enabled"

\* Legal holds exist only on lock-enabled buckets and never on delete markers.
HoldsWellFormed ==
    \A k \in Keys : \A i \in 1..Len(objects[k]) :
        objects[k][i].hold => (lock /\ ~objects[k][i].dm)

\* Fresh IDs grow with recency: newer non-null versions have larger IDs.
NewestFirst ==
    \A k \in Keys : \A i, j \in 1..Len(objects[k]) :
        (i < j /\ objects[k][i].id # Null /\ objects[k][j].id # Null)
            => objects[k][i].id > objects[k][j].id

Invariants ==
    TypeOK /\ NullUnique /\ IdsUnique /\ UnversionedOnlyNull
    /\ LockImpliesEnabled /\ HoldsWellFormed /\ NewestFirst

----------------------------------------------------------------------------
(* Action / temporal properties *)

\* A bucket that was ever versioned never returns to unversioned.
NeverUnversionedAgain == [][versioning # "Unset" => versioning' # "Unset"]_vars

\* Object Lock can never be turned off.
LockIsPermanent == [][lock => lock']_vars

\* A version under legal hold is never removed or altered except through
\* its hold flag (no step deletes or overwrites it).
HeldVersionsSurvive ==
    [][\A k \in Keys : \A i \in 1..Len(objects[k]) :
        objects[k][i].hold =>
            \E j \in 1..Len(objects'[k]) :
                objects'[k][j].id = objects[k][i].id /\ ~objects'[k][j].dm]_vars

\* Writes while versioning is Enabled never destroy existing versions.
EnabledWritesPreserveHistory ==
    [][(versioning = "Enabled" /\ \E k \in Keys : Put(k) \/ Delete(k)) =>
        \A k \in Keys : IdsOf(k) \subseteq IdsOf(k)']_vars

=============================================================================
