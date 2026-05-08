------------- MODULE LockSpecFIFO_PartialVisibility_Fixed -------------
(***************************************************************************)
(* Same partial-visibility scenario as LockSpecFIFO_PartialVisibility,    *)
(* but now models the warm-start guard implemented by                     *)
(* Config.LockAcquireMembershipWait + Alan.membershipSettled.             *)
(*                                                                         *)
(* Behavioural change relative to the buggy spec:                         *)
(*   - Each peer carries a `settled` boolean, initially FALSE.            *)
(*   - AcquireStart and AcquireNoPeers gate on `settled[self] = TRUE`.    *)
(*   - A new Settle(p) action flips settled[p] to TRUE only when         *)
(*     visible[p] = Peers \ {p} (i.e. full membership locally).          *)
(*                                                                         *)
(* This corresponds to LockAcquireMembershipWait being long enough that  *)
(* the wait succeeds (full membership reached) before the timeout         *)
(* elapses. The Go implementation also accepts a timeout-only settle     *)
(* (fail-open) which is faster but reintroduces the original race when   *)
(* the timeout is too short — that path is documented in README and is   *)
(* deliberately NOT modelled here so we can prove the fix is correct in  *)
(* its strict form.                                                       *)
(*                                                                         *)
(* Expected TLC outcome: MutualExclusion holds. The buggy 5-step         *)
(* counter-example is impossible because peer p2 cannot fire             *)
(* AcquireStart while visible[p2] = {p3} (partial membership) — settled  *)
(* is still FALSE.                                                        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Peers,
    MaxAttempts,
    RequireQuorum,
    EnableDisconnect,
    PreHeldPeer

ASSUME RequireQuorum    \in BOOLEAN
ASSUME EnableDisconnect \in BOOLEAN
ASSUME MaxAttempts \in Nat /\ MaxAttempts >= 1
ASSUME PreHeldPeer \in Peers

QuorumSize == (Cardinality(Peers) \div 2) + 1

StateFree      == [tag |-> "Free"]
StatePending   == [tag |-> "Pending"]
StateSelfHeld  == [tag |-> "SelfHeld"]
StateHeldBy(q) == [tag |-> "HeldBy", who |-> q]

ReqID(p, n) == [peer |-> p, num |-> n]
NoReq       == [peer |-> 0, num |-> 0]

PeerIdx == CHOOSE f \in [Peers -> 1..Cardinality(Peers)] :
              \A p, q \in Peers : p # q => f[p] # f[q]

ReqLT(a, b) == \/ PeerIdx[a.peer] < PeerIdx[b.peer]
               \/ /\ a.peer = b.peer
                  /\ a.num  < b.num

MsgRequest(id) == [type |-> "Req",   id |-> id]
MsgGrant(id)   == [type |-> "Grant", id |-> id]
MsgDeny(id)    == [type |-> "Deny",  id |-> id]
MsgRelease(id) == [type |-> "Rel",   id |-> id]

(*--algorithm LockFIFO_PV_Fixed

variables
    state    = [p \in Peers |-> IF p = PreHeldPeer
                                THEN StateSelfHeld
                                ELSE StateFree],
    myReq    = [p \in Peers |-> NoReq],
    grants   = [p \in Peers |-> {}],
    expected = [p \in Peers |-> {}],
    visible  = [p \in Peers |-> {}],
    attempts = [p \in Peers |-> IF p = PreHeldPeer THEN 1 ELSE 0],
    severed  = {},
    inbox    = [from \in Peers |-> [to \in Peers |-> << >>]],
    heldByID = [p \in Peers |-> NoReq],
    \* Warm-start guard. PreHeldPeer is born already settled (it
    \* successfully acquired earlier; in the real code,
    \* membershipSettled is set on the first wait that reaches full
    \* membership OR times out). All other peers must reach full
    \* visibility before they may attempt to acquire.
    settled  = [p \in Peers |-> p = PreHeldPeer];

define
    HasQuorum(p) == (~RequireQuorum)
                  \/ ((Cardinality(visible[p]) + 1) >= QuorumSize)

    \* Full visibility check used by Settle below. visible excludes
    \* self by construction, so the comparison is to Peers \ {self}.
    HasFullMembership(p) == visible[p] = Peers \ {p}

    Holders         == { p \in Peers : state[p] = StateSelfHeld }
    MutualExclusion == Cardinality(Holders) <= 1

    TypeInv ==
        /\ visible  \in [Peers -> SUBSET Peers]
        /\ attempts \in [Peers -> 0..MaxAttempts]
        /\ settled  \in [Peers -> BOOLEAN]
        /\ \A p \in Peers :
              \/ state[p] = StateFree
              \/ state[p] = StatePending
              \/ state[p] = StateSelfHeld
              \/ /\ state[p].tag = "HeldBy"
                 /\ state[p].who \in Peers
end define;

process Peer \in Peers
begin Loop:
    while TRUE do
        either
            (* ---- Connect ---- *)
            await visible[self] # (Peers \ {self});
            with q \in (Peers \ {self}) \ visible[self] do
                await {self, q} \notin severed;
                visible[self] := visible[self] \cup {q} ||
                visible[q]    := visible[q]    \cup {self};
            end with;

        or
            (* ---- Settle: warm-start guard releases when full
               membership is reached locally. ---- *)
            await ~settled[self] /\ HasFullMembership(self);
            settled[self] := TRUE;

        or
            (* ---- AcquireNoPeers ---- *)
            await /\ settled[self]
                  /\ state[self]   = StateFree
                  /\ visible[self] = {}
                  /\ attempts[self] < MaxAttempts
                  /\ HasQuorum(self);
            attempts[self] := attempts[self] + 1 ||
            state[self]    := StateSelfHeld;

        or
            (* ---- AcquireStart ---- *)
            await /\ settled[self]
                  /\ state[self]   = StateFree
                  /\ visible[self] # {}
                  /\ attempts[self] < MaxAttempts
                  /\ HasQuorum(self);
            with newAttempt = attempts[self] + 1,
                 rid        = ReqID(self, newAttempt),
                 vis        = visible[self] do
                attempts[self] := newAttempt ||
                state[self]    := StatePending ||
                myReq[self]    := rid ||
                grants[self]   := {} ||
                expected[self] := vis ||
                inbox          := [f \in Peers |->
                                     IF f = self
                                     THEN [t \in Peers |->
                                              IF t \in vis
                                              THEN Append(inbox[self][t],
                                                          MsgRequest(rid))
                                              ELSE inbox[self][t]]
                                     ELSE inbox[f]];
            end with;

        or
            (* ---- ReceiveRequest ---- *)
            with from \in Peers do
                await /\ from # self
                      /\ Len(inbox[from][self]) > 0
                      /\ Head(inbox[from][self]).type = "Req";
                with m = Head(inbox[from][self]) do
                    if state[self] = StateFree then
                        state[self]    := StateHeldBy(from) ||
                        heldByID[self] := m.id ||
                        inbox          := [inbox EXCEPT
                            ![from][self] = Tail(inbox[from][self]),
                            ![self][from] = Append(@, MsgGrant(m.id))];
                    elsif state[self].tag = "HeldBy" \/ state[self] = StateSelfHeld then
                        inbox := [inbox EXCEPT
                            ![from][self] = Tail(inbox[from][self]),
                            ![self][from] = Append(@, MsgDeny(m.id))];
                    elsif state[self] = StatePending then
                        if ReqLT(m.id, myReq[self]) then
                            with myOldReq = myReq[self], vis = visible[self] do
                                state[self]    := StateHeldBy(from) ||
                                heldByID[self] := m.id ||
                                myReq[self]    := NoReq ||
                                grants[self]   := {} ||
                                expected[self] := {} ||
                                inbox := [f \in Peers |->
                                    IF f = from
                                    THEN [t \in Peers |->
                                            IF t = self
                                            THEN Tail(inbox[from][self])
                                            ELSE inbox[from][t]]
                                    ELSE IF f = self
                                         THEN [t \in Peers |->
                                                 IF t = from
                                                 THEN Append(inbox[self][from],
                                                             MsgGrant(m.id))
                                                 ELSE IF t \in vis
                                                      THEN Append(inbox[self][t],
                                                                  MsgRelease(myOldReq))
                                                      ELSE inbox[self][t]]
                                         ELSE inbox[f]];
                            end with;
                        else
                            inbox := [inbox EXCEPT
                                ![from][self] = Tail(inbox[from][self]),
                                ![self][from] = Append(@, MsgDeny(m.id))];
                        end if;
                    end if;
                end with;
            end with;

        or
            (* ---- ReceiveGrant ---- *)
            with from \in Peers do
                await /\ from # self
                      /\ Len(inbox[from][self]) > 0
                      /\ Head(inbox[from][self]).type = "Grant"
                      /\ state[self] = StatePending
                      /\ Head(inbox[from][self]).id = myReq[self];
                with m = Head(inbox[from][self]) do
                    if expected[self] \subseteq (grants[self] \cup {from}) then
                        state[self]    := StateSelfHeld ||
                        myReq[self]    := NoReq ||
                        grants[self]   := {} ||
                        expected[self] := {} ||
                        inbox          := [inbox EXCEPT
                            ![from][self] = Tail(inbox[from][self])];
                    else
                        grants[self] := grants[self] \cup {from} ||
                        inbox        := [inbox EXCEPT
                            ![from][self] = Tail(inbox[from][self])];
                    end if;
                end with;
            end with;

        or
            (* ---- ReceiveDeny ---- *)
            with from \in Peers do
                await /\ from # self
                      /\ Len(inbox[from][self]) > 0
                      /\ Head(inbox[from][self]).type = "Deny"
                      /\ state[self] = StatePending
                      /\ Head(inbox[from][self]).id = myReq[self];
                with myOldReq = myReq[self], vis = visible[self] do
                    state[self]    := StateFree ||
                    myReq[self]    := NoReq ||
                    grants[self]   := {} ||
                    expected[self] := {} ||
                    inbox := [f \in Peers |->
                        IF f = from
                        THEN [t \in Peers |->
                                IF t = self
                                THEN Tail(inbox[from][self])
                                ELSE inbox[from][t]]
                        ELSE IF f = self
                             THEN [t \in Peers |->
                                     IF t \in vis
                                     THEN Append(inbox[self][t],
                                                 MsgRelease(myOldReq))
                                     ELSE inbox[self][t]]
                             ELSE inbox[f]];
                end with;
            end with;

        or
            (* ---- DropDeny ---- *)
            with from \in Peers do
                await /\ from # self
                      /\ Len(inbox[from][self]) > 0
                      /\ Head(inbox[from][self]).type = "Deny"
                      /\ \/ state[self] # StatePending
                         \/ Head(inbox[from][self]).id # myReq[self];
                inbox := [inbox EXCEPT
                    ![from][self] = Tail(inbox[from][self])];
            end with;

        or
            (* ---- DropGrant ---- *)
            with from \in Peers do
                await /\ from # self
                      /\ Len(inbox[from][self]) > 0
                      /\ Head(inbox[from][self]).type = "Grant"
                      /\ \/ state[self] # StatePending
                         \/ Head(inbox[from][self]).id # myReq[self];
                inbox := [inbox EXCEPT
                    ![from][self] = Tail(inbox[from][self])];
            end with;

        or
            (* ---- ReceiveRelease ---- *)
            with from \in Peers do
                await /\ from # self
                      /\ Len(inbox[from][self]) > 0
                      /\ Head(inbox[from][self]).type = "Rel";
                with m = Head(inbox[from][self]) do
                    if /\ state[self].tag = "HeldBy"
                       /\ state[self].who = from
                       /\ heldByID[self]  = m.id then
                        state[self]    := StateFree ||
                        heldByID[self] := NoReq ||
                        inbox          := [inbox EXCEPT
                            ![from][self] = Tail(inbox[from][self])];
                    else
                        inbox := [inbox EXCEPT
                            ![from][self] = Tail(inbox[from][self])];
                    end if;
                end with;
            end with;

        or
            (* ---- Disconnect ---- *)
            await EnableDisconnect /\ visible[self] # {};
            with q \in visible[self] do
                visible[self] := visible[self] \ {q} ||
                visible[q]    := visible[q]    \ {self} ||
                severed       := severed \cup { {self, q} } ||

                state[self]    := IF state[self].tag = "HeldBy"
                                    /\ state[self].who = q
                                  THEN StateFree
                                  ELSE state[self] ||
                state[q]       := IF state[q].tag = "HeldBy"
                                    /\ state[q].who = self
                                  THEN StateFree
                                  ELSE state[q] ||
                heldByID[self] := IF state[self].tag = "HeldBy"
                                    /\ state[self].who = q
                                  THEN NoReq
                                  ELSE heldByID[self] ||
                heldByID[q]    := IF state[q].tag = "HeldBy"
                                    /\ state[q].who = self
                                  THEN NoReq
                                  ELSE heldByID[q] ||

                expected[self] := IF state[self] = StatePending
                                  THEN expected[self] \ {q}
                                  ELSE expected[self] ||
                expected[q]    := IF state[q] = StatePending
                                  THEN expected[q] \ {self}
                                  ELSE expected[q] ||

                inbox          := [inbox EXCEPT
                    ![self][q] = << >>,
                    ![q][self] = << >>];
            end with;
        end either;
    end while;
end process;

end algorithm; *)
\* BEGIN TRANSLATION (chksum(pcal) = "c4efa9a8" /\ chksum(tla) = "671d1614")
VARIABLES state, myReq, grants, expected, visible, attempts, severed, inbox, 
          heldByID, settled

(* define statement *)
HasQuorum(p) == (~RequireQuorum)
              \/ ((Cardinality(visible[p]) + 1) >= QuorumSize)



HasFullMembership(p) == visible[p] = Peers \ {p}

Holders         == { p \in Peers : state[p] = StateSelfHeld }
MutualExclusion == Cardinality(Holders) <= 1

TypeInv ==
    /\ visible  \in [Peers -> SUBSET Peers]
    /\ attempts \in [Peers -> 0..MaxAttempts]
    /\ settled  \in [Peers -> BOOLEAN]
    /\ \A p \in Peers :
          \/ state[p] = StateFree
          \/ state[p] = StatePending
          \/ state[p] = StateSelfHeld
          \/ /\ state[p].tag = "HeldBy"
             /\ state[p].who \in Peers


vars == << state, myReq, grants, expected, visible, attempts, severed, inbox, 
           heldByID, settled >>

ProcSet == (Peers)

Init == (* Global variables *)
        /\ state = [p \in Peers |-> IF p = PreHeldPeer
                                    THEN StateSelfHeld
                                    ELSE StateFree]
        /\ myReq = [p \in Peers |-> NoReq]
        /\ grants = [p \in Peers |-> {}]
        /\ expected = [p \in Peers |-> {}]
        /\ visible = [p \in Peers |-> {}]
        /\ attempts = [p \in Peers |-> IF p = PreHeldPeer THEN 1 ELSE 0]
        /\ severed = {}
        /\ inbox = [from \in Peers |-> [to \in Peers |-> << >>]]
        /\ heldByID = [p \in Peers |-> NoReq]
        /\ settled = [p \in Peers |-> p = PreHeldPeer]

Peer(self) == \/ /\ visible[self] # (Peers \ {self})
                 /\ \E q \in (Peers \ {self}) \ visible[self]:
                      /\ {self, q} \notin severed
                      /\ visible' = [visible EXCEPT ![self] = visible[self] \cup {q},
                                                    ![q] = visible[q]    \cup {self}]
                 /\ UNCHANGED <<state, myReq, grants, expected, attempts, severed, inbox, heldByID, settled>>
              \/ /\ ~settled[self] /\ HasFullMembership(self)
                 /\ settled' = [settled EXCEPT ![self] = TRUE]
                 /\ UNCHANGED <<state, myReq, grants, expected, visible, attempts, severed, inbox, heldByID>>
              \/ /\ /\ settled[self]
                    /\ state[self]   = StateFree
                    /\ visible[self] = {}
                    /\ attempts[self] < MaxAttempts
                    /\ HasQuorum(self)
                 /\ /\ attempts' = [attempts EXCEPT ![self] = attempts[self] + 1]
                    /\ state' = [state EXCEPT ![self] = StateSelfHeld]
                 /\ UNCHANGED <<myReq, grants, expected, visible, severed, inbox, heldByID, settled>>
              \/ /\ /\ settled[self]
                    /\ state[self]   = StateFree
                    /\ visible[self] # {}
                    /\ attempts[self] < MaxAttempts
                    /\ HasQuorum(self)
                 /\ LET newAttempt == attempts[self] + 1 IN
                      LET rid == ReqID(self, newAttempt) IN
                        LET vis == visible[self] IN
                          /\ attempts' = [attempts EXCEPT ![self] = newAttempt]
                          /\ expected' = [expected EXCEPT ![self] = vis]
                          /\ grants' = [grants EXCEPT ![self] = {}]
                          /\ inbox' = [f \in Peers |->
                                         IF f = self
                                         THEN [t \in Peers |->
                                                  IF t \in vis
                                                  THEN Append(inbox[self][t],
                                                              MsgRequest(rid))
                                                  ELSE inbox[self][t]]
                                         ELSE inbox[f]]
                          /\ myReq' = [myReq EXCEPT ![self] = rid]
                          /\ state' = [state EXCEPT ![self] = StatePending]
                 /\ UNCHANGED <<visible, severed, heldByID, settled>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Req"
                      /\ LET m == Head(inbox[from][self]) IN
                           IF state[self] = StateFree
                              THEN /\ /\ heldByID' = [heldByID EXCEPT ![self] = m.id]
                                      /\ inbox' =               [inbox EXCEPT
                                                  ![from][self] = Tail(inbox[from][self]),
                                                  ![self][from] = Append(@, MsgGrant(m.id))]
                                      /\ state' = [state EXCEPT ![self] = StateHeldBy(from)]
                                   /\ UNCHANGED << myReq, grants, expected >>
                              ELSE /\ IF state[self].tag = "HeldBy" \/ state[self] = StateSelfHeld
                                         THEN /\ inbox' =      [inbox EXCEPT
                                                          ![from][self] = Tail(inbox[from][self]),
                                                          ![self][from] = Append(@, MsgDeny(m.id))]
                                              /\ UNCHANGED << state, myReq, 
                                                              grants, 
                                                              expected, 
                                                              heldByID >>
                                         ELSE /\ IF state[self] = StatePending
                                                    THEN /\ IF ReqLT(m.id, myReq[self])
                                                               THEN /\ LET myOldReq == myReq[self] IN
                                                                         LET vis == visible[self] IN
                                                                           /\ expected' = [expected EXCEPT ![self] = {}]
                                                                           /\ grants' = [grants EXCEPT ![self] = {}]
                                                                           /\ heldByID' = [heldByID EXCEPT ![self] = m.id]
                                                                           /\ inbox' =      [f \in Peers |->
                                                                                       IF f = from
                                                                                       THEN [t \in Peers |->
                                                                                               IF t = self
                                                                                               THEN Tail(inbox[from][self])
                                                                                               ELSE inbox[from][t]]
                                                                                       ELSE IF f = self
                                                                                            THEN [t \in Peers |->
                                                                                                    IF t = from
                                                                                                    THEN Append(inbox[self][from],
                                                                                                                MsgGrant(m.id))
                                                                                                    ELSE IF t \in vis
                                                                                                         THEN Append(inbox[self][t],
                                                                                                                     MsgRelease(myOldReq))
                                                                                                         ELSE inbox[self][t]]
                                                                                            ELSE inbox[f]]
                                                                           /\ myReq' = [myReq EXCEPT ![self] = NoReq]
                                                                           /\ state' = [state EXCEPT ![self] = StateHeldBy(from)]
                                                               ELSE /\ inbox' =      [inbox EXCEPT
                                                                                ![from][self] = Tail(inbox[from][self]),
                                                                                ![self][from] = Append(@, MsgDeny(m.id))]
                                                                    /\ UNCHANGED << state, 
                                                                                    myReq, 
                                                                                    grants, 
                                                                                    expected, 
                                                                                    heldByID >>
                                                    ELSE /\ TRUE
                                                         /\ UNCHANGED << state, 
                                                                         myReq, 
                                                                         grants, 
                                                                         expected, 
                                                                         inbox, 
                                                                         heldByID >>
                 /\ UNCHANGED <<visible, attempts, severed, settled>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Grant"
                         /\ state[self] = StatePending
                         /\ Head(inbox[from][self]).id = myReq[self]
                      /\ LET m == Head(inbox[from][self]) IN
                           IF expected[self] \subseteq (grants[self] \cup {from})
                              THEN /\ /\ expected' = [expected EXCEPT ![self] = {}]
                                      /\ grants' = [grants EXCEPT ![self] = {}]
                                      /\ inbox' =               [inbox EXCEPT
                                                  ![from][self] = Tail(inbox[from][self])]
                                      /\ myReq' = [myReq EXCEPT ![self] = NoReq]
                                      /\ state' = [state EXCEPT ![self] = StateSelfHeld]
                              ELSE /\ /\ grants' = [grants EXCEPT ![self] = grants[self] \cup {from}]
                                      /\ inbox' =             [inbox EXCEPT
                                                  ![from][self] = Tail(inbox[from][self])]
                                   /\ UNCHANGED << state, myReq, expected >>
                 /\ UNCHANGED <<visible, attempts, severed, heldByID, settled>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Deny"
                         /\ state[self] = StatePending
                         /\ Head(inbox[from][self]).id = myReq[self]
                      /\ LET myOldReq == myReq[self] IN
                           LET vis == visible[self] IN
                             /\ expected' = [expected EXCEPT ![self] = {}]
                             /\ grants' = [grants EXCEPT ![self] = {}]
                             /\ inbox' =      [f \in Peers |->
                                         IF f = from
                                         THEN [t \in Peers |->
                                                 IF t = self
                                                 THEN Tail(inbox[from][self])
                                                 ELSE inbox[from][t]]
                                         ELSE IF f = self
                                              THEN [t \in Peers |->
                                                      IF t \in vis
                                                      THEN Append(inbox[self][t],
                                                                  MsgRelease(myOldReq))
                                                      ELSE inbox[self][t]]
                                              ELSE inbox[f]]
                             /\ myReq' = [myReq EXCEPT ![self] = NoReq]
                             /\ state' = [state EXCEPT ![self] = StateFree]
                 /\ UNCHANGED <<visible, attempts, severed, heldByID, settled>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Deny"
                         /\ \/ state[self] # StatePending
                            \/ Head(inbox[from][self]).id # myReq[self]
                      /\ inbox' =      [inbox EXCEPT
                                  ![from][self] = Tail(inbox[from][self])]
                 /\ UNCHANGED <<state, myReq, grants, expected, visible, attempts, severed, heldByID, settled>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Grant"
                         /\ \/ state[self] # StatePending
                            \/ Head(inbox[from][self]).id # myReq[self]
                      /\ inbox' =      [inbox EXCEPT
                                  ![from][self] = Tail(inbox[from][self])]
                 /\ UNCHANGED <<state, myReq, grants, expected, visible, attempts, severed, heldByID, settled>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Rel"
                      /\ LET m == Head(inbox[from][self]) IN
                           IF /\ state[self].tag = "HeldBy"
                              /\ state[self].who = from
                              /\ heldByID[self]  = m.id
                              THEN /\ /\ heldByID' = [heldByID EXCEPT ![self] = NoReq]
                                      /\ inbox' =               [inbox EXCEPT
                                                  ![from][self] = Tail(inbox[from][self])]
                                      /\ state' = [state EXCEPT ![self] = StateFree]
                              ELSE /\ inbox' =      [inbox EXCEPT
                                               ![from][self] = Tail(inbox[from][self])]
                                   /\ UNCHANGED << state, heldByID >>
                 /\ UNCHANGED <<myReq, grants, expected, visible, attempts, severed, settled>>
              \/ /\ EnableDisconnect /\ visible[self] # {}
                 /\ \E q \in visible[self]:
                      /\ expected' = [expected EXCEPT ![self] = IF state[self] = StatePending
                                                                THEN expected[self] \ {q}
                                                                ELSE expected[self],
                                                      ![q] = IF state[q] = StatePending
                                                             THEN expected[q] \ {self}
                                                             ELSE expected[q]]
                      /\ heldByID' = [heldByID EXCEPT ![self] = IF state[self].tag = "HeldBy"
                                                                  /\ state[self].who = q
                                                                THEN NoReq
                                                                ELSE heldByID[self],
                                                      ![q] = IF state[q].tag = "HeldBy"
                                                               /\ state[q].who = self
                                                             THEN NoReq
                                                             ELSE heldByID[q]]
                      /\ inbox' =               [inbox EXCEPT
                                  ![self][q] = << >>,
                                  ![q][self] = << >>]
                      /\ severed' = (severed \cup { {self, q} })
                      /\ state' = [state EXCEPT ![self] = IF state[self].tag = "HeldBy"
                                                            /\ state[self].who = q
                                                          THEN StateFree
                                                          ELSE state[self],
                                                ![q] = IF state[q].tag = "HeldBy"
                                                         /\ state[q].who = self
                                                       THEN StateFree
                                                       ELSE state[q]]
                      /\ visible' = [visible EXCEPT ![self] = visible[self] \ {q},
                                                    ![q] = visible[q]    \ {self}]
                 /\ UNCHANGED <<myReq, grants, attempts, settled>>

Next == (\E self \in Peers: Peer(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION 

=============================================================================
