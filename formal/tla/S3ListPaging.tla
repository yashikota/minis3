---------------------------- MODULE S3ListPaging ----------------------------
(***************************************************************************)
(* Model of the continuation-marker rules shared by minis3's list APIs     *)
(* (ListObjects V1/V2, ListObjectVersions, ListMultipartUploads; see       *)
(* internal/backend/object.go and multipart.go).                           *)
(*                                                                         *)
(* Keys are sequences over a tiny alphabet (0 plays the delimiter "/") and *)
(* are ordered lexicographically, like Go string comparison. Each key      *)
(* carries 1..MaxVersions entries (versions or uploads). A listing with a  *)
(* delimiter rolls every key that has the delimiter after the prefix up    *)
(* into one CommonPrefix entry. The implementation's rules are:            *)
(*                                                                         *)
(*  R1 every CommonPrefix occupies one slot and counts toward max-keys;    *)
(*  R2 a page holds the first max-keys entries after the marker;           *)
(*  R3 the next marker is the (key, version) of the page's last entry,     *)
(*     with no version for a CommonPrefix;                                 *)
(*  R4 resuming from (key, version) starts right after that exact entry;   *)
(*     from a bare key, at the first entry whose key is greater.           *)
(*                                                                         *)
(* TLC checks, for every key set, version count, prefix, delimiter choice  *)
(* and page size in the bounds, that following the markers returns every   *)
(* entry exactly once and in order, that IsTruncated is set exactly when   *)
(* entries remain, and that paging terminates. The Go property test        *)
(* internal/backend/paging_property_test.go checks the implementation      *)
(* against the same oracle on random inputs.                               *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Alphabet,     \* symbols, e.g. {0, 1}; 0 is the delimiter
          MaxLen,       \* longest key
          MaxVersions,  \* entries per key
          MaxPage       \* largest max-keys tried

Delim == 0
NoVersion == 0

Universe == UNION {[1..n -> Alphabet] : n \in 1..MaxLen}
Prefixes == {<<>>} \cup {<<a>> : a \in Alphabet \ {Delim}}

RECURSIVE LexLT(_, _)
LexLT(s, t) ==
    IF Len(s) = 0 THEN Len(t) > 0
    ELSE IF Len(t) = 0 THEN FALSE
    ELSE IF Head(s) # Head(t) THEN Head(s) < Head(t)
    ELSE LexLT(Tail(s), Tail(t))

IsPrefix(p, s) == Len(p) <= Len(s) /\ SubSeq(s, 1, Len(p)) = p

\* Position of the first delimiter after the prefix, or 0.
DelimAt(p, k) ==
    LET pos == {i \in (Len(p) + 1)..Len(k) : k[i] = Delim}
    IN  IF pos = {} THEN 0 ELSE CHOOSE i \in pos : \A j \in pos : i <= j

\* Entry ordering: by key, then by version index (version 1 sorts first,
\* standing for "newest" / "earliest initiated").
EntryLT(e, f) == LexLT(e.key, f.key) \/ (e.key = f.key /\ e.v < f.v)

VARIABLES keys,      \* the key set being listed
          nv,        \* nv[k] = number of entries of key k
          prefix,
          useDelim,
          maxKeys,
          marker,    \* [key, v]; the empty key means "no marker"
          got,       \* entries returned so far, in order
          done,      \* the last page had IsTruncated = false
          pages,
          exp        \* the expected full listing, fixed at Init

vars == <<keys, nv, prefix, useDelim, maxKeys, marker, got, done, pages, exp>>

\* The full, unpaged listing as a set of entries (rule R1).
EntrySet ==
    LET under == {k \in keys : IsPrefix(prefix, k)}
        rolled == {k \in under : useDelim /\ DelimAt(prefix, k) # 0}
        cps == {[key |-> SubSeq(k, 1, DelimAt(prefix, k)), v |-> NoVersion] : k \in rolled}
        plain == UNION {{[key |-> k, v |-> i] : i \in 1..nv[k]} : k \in under \ rolled}
    IN  cps \cup plain

\* EntrySet sorted into a sequence.
Rank(e) == Cardinality({f \in EntrySet : EntryLT(f, e)})
Expected == [i \in 1..Cardinality(EntrySet) |-> CHOOSE e \in EntrySet : Rank(e) = i - 1]

\* Rule R4: is entry e after the marker?
\* Keys are non-empty, so the empty marker key precedes every entry.
After(e) ==
    IF marker.v # NoVersion
    THEN LexLT(marker.key, e.key) \/ (e.key = marker.key /\ e.v > marker.v)
    ELSE LexLT(marker.key, e.key)

Remaining == {i \in 1..Len(exp) : After(exp[i])}

Init ==
    /\ keys \in SUBSET Universe
    /\ nv \in [keys -> 1..MaxVersions]
    /\ prefix \in Prefixes
    /\ useDelim \in BOOLEAN
    /\ maxKeys \in 1..MaxPage
    /\ marker = [key |-> <<>>, v |-> NoVersion]
    /\ got = <<>>
    /\ done = FALSE
    /\ pages = 0
    /\ exp = Expected

\* One list call (rules R2 and R3).
Page ==
    /\ ~done
    /\ LET idx == Remaining
           first == IF idx = {} THEN 1 ELSE CHOOSE i \in idx : \A j \in idx : i <= j
           count == IF Cardinality(idx) < maxKeys THEN Cardinality(idx) ELSE maxKeys
           page == SubSeq(exp, first, first + count - 1)
           truncated == Cardinality(idx) > maxKeys
       IN  /\ got' = got \o page
           /\ done' = ~truncated
           /\ marker' = IF truncated THEN page[Len(page)] ELSE marker
           /\ pages' = pages + 1
    /\ UNCHANGED <<keys, nv, prefix, useDelim, maxKeys, exp>>

Next == Page \/ (done /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ WF_vars(Page)

----------------------------------------------------------------------------
(* Properties *)

\* Entries come back in listing order with no duplicates or gaps.
OrderedNoDuplicates == got = SubSeq(exp, 1, Len(got))

\* When paging stops, every entry has been returned.
CompleteWhenDone == done => got = exp

\* Paging terminates within the number of entries plus one call.
BoundedPages == pages <= Len(exp) + 1

Termination == <>done

=============================================================================
