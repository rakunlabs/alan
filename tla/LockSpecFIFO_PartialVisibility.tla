--------------------- MODULE LockSpecFIFO_PartialVisibility ---------------------
(***************************************************************************)
(* Partial-visibility startup race.                                        *)
(*                                                                         *)
(* Models a 3-peer cluster where peer p1 has ALREADY acquired the lock    *)
(* before p2 and p3 finish their handshakes. After p2 and p3 boot they    *)
(* establish a QUIC handshake with each other (Connect: p2 ↔ p3) before  *)
(* they finish their handshakes with p1 — a common race during DNS       *)
(* propagation or Kubernetes rolling startup.                             *)
(*                                                                        *)
(* In that intermediate state visible[p2] = {p3} and HasQuorum(p2) is    *)
(* satisfied (|visible| + 1 = 2 ≥ majority(3) = 2), so p2 can fire        *)
(* AcquireStart against p3 alone and successfully transition to          *)
(* SelfHeld. p1 is still SelfHeld. Mutual exclusion violated.             *)
(*                                                                        *)
(* This spec extends LockSpecFIFO with an asymmetric Init: p1 starts in   *)
(* SelfHeld with attempts[p1]=1 (i.e. it acquired the lock during a      *)
(* "no peers yet" startup era). p2 and p3 start in the normal Free state. *)
(* All other actions are inherited.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Peers,
    MaxAttempts,
    RequireQuorum,
    EnableDisconnect,
    PreHeldPeer  \* the peer that starts in SelfHeld

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

(*--algorithm LockFIFO_PV

variables
    \* Asymmetric init: PreHeldPeer is already SelfHeld, attempts=1.
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
    heldByID = [p \in Peers |-> NoReq];

define
    HasQuorum(p) == (~RequireQuorum)
                  \/ ((Cardinality(visible[p]) + 1) >= QuorumSize)

    Holders         == { p \in Peers : state[p] = StateSelfHeld }
    MutualExclusion == Cardinality(Holders) <= 1

    TypeInv ==
        /\ visible  \in [Peers -> SUBSET Peers]
        /\ attempts \in [Peers -> 0..MaxAttempts]
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
            (* ---- AcquireNoPeers ---- *)
            await /\ state[self]   = StateFree
                  /\ visible[self] = {}
                  /\ attempts[self] < MaxAttempts
                  /\ HasQuorum(self);
            attempts[self] := attempts[self] + 1 ||
            state[self]    := StateSelfHeld;

        or
            (* ---- AcquireStart ---- *)
            await /\ state[self]   = StateFree
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
            (* ---- ReceiveDeny: abort, broadcast Release tagged with myReq ---- *)
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
\* BEGIN TRANSLATION (chksum(pcal) = "746f5e9d" /\ chksum(tla) = "a51f0aaf")
VARIABLES state, myReq, grants, expected, visible, attempts, severed, inbox, 
          heldByID

(* define statement *)
HasQuorum(p) == (~RequireQuorum)
              \/ ((Cardinality(visible[p]) + 1) >= QuorumSize)

Holders         == { p \in Peers : state[p] = StateSelfHeld }
MutualExclusion == Cardinality(Holders) <= 1

TypeInv ==
    /\ visible  \in [Peers -> SUBSET Peers]
    /\ attempts \in [Peers -> 0..MaxAttempts]
    /\ \A p \in Peers :
          \/ state[p] = StateFree
          \/ state[p] = StatePending
          \/ state[p] = StateSelfHeld
          \/ /\ state[p].tag = "HeldBy"
             /\ state[p].who \in Peers


vars == << state, myReq, grants, expected, visible, attempts, severed, inbox, 
           heldByID >>

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

Peer(self) == \/ /\ visible[self] # (Peers \ {self})
                 /\ \E q \in (Peers \ {self}) \ visible[self]:
                      /\ {self, q} \notin severed
                      /\ visible' = [visible EXCEPT ![self] = visible[self] \cup {q},
                                                    ![q] = visible[q]    \cup {self}]
                 /\ UNCHANGED <<state, myReq, grants, expected, attempts, severed, inbox, heldByID>>
              \/ /\ /\ state[self]   = StateFree
                    /\ visible[self] = {}
                    /\ attempts[self] < MaxAttempts
                    /\ HasQuorum(self)
                 /\ /\ attempts' = [attempts EXCEPT ![self] = attempts[self] + 1]
                    /\ state' = [state EXCEPT ![self] = StateSelfHeld]
                 /\ UNCHANGED <<myReq, grants, expected, visible, severed, inbox, heldByID>>
              \/ /\ /\ state[self]   = StateFree
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
                 /\ UNCHANGED <<visible, severed, heldByID>>
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
                 /\ UNCHANGED <<visible, attempts, severed>>
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
                 /\ UNCHANGED <<visible, attempts, severed, heldByID>>
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
                 /\ UNCHANGED <<visible, attempts, severed, heldByID>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Deny"
                         /\ \/ state[self] # StatePending
                            \/ Head(inbox[from][self]).id # myReq[self]
                      /\ inbox' =      [inbox EXCEPT
                                  ![from][self] = Tail(inbox[from][self])]
                 /\ UNCHANGED <<state, myReq, grants, expected, visible, attempts, severed, heldByID>>
              \/ /\ \E from \in Peers:
                      /\ /\ from # self
                         /\ Len(inbox[from][self]) > 0
                         /\ Head(inbox[from][self]).type = "Grant"
                         /\ \/ state[self] # StatePending
                            \/ Head(inbox[from][self]).id # myReq[self]
                      /\ inbox' =      [inbox EXCEPT
                                  ![from][self] = Tail(inbox[from][self])]
                 /\ UNCHANGED <<state, myReq, grants, expected, visible, attempts, severed, heldByID>>
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
                 /\ UNCHANGED <<myReq, grants, expected, visible, attempts, severed>>
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
                 /\ UNCHANGED <<myReq, grants, attempts>>

Next == (\E self \in Peers: Peer(self))

Spec == Init /\ [][Next]_vars

\* END TRANSLATION 

=============================================================================
