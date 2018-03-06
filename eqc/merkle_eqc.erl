-module(merkle_eqc).

%% include some quickcheck headers
-include_lib("eqc/include/eqc.hrl").

-export([prop_merkle/0]).

prop_merkle() ->
    %% generate 2 disjoint lists of binaries
    ?FORALL({Values, NonValues}, ?SUCHTHAT({X1, X2}, {list(binary()), list(binary())}, sets:is_disjoint(sets:from_list(X1), sets:from_list(X2))),
            begin
                try
                    UniqueValues = Values -- (Values -- lists:usort(Values)),
                    Tree = merkle:new(Values, fun merkle:hash_value/1),
                    RootHash = merkle:root_hash(Tree),
                    NonTree = merkle:new(NonValues, fun merkle:hash_value/1),
                    ValuesAndProofs = [ {V, merkle:gen_proof(merkle:hash_value(V), Tree)} || V <- Values ],
                    NoEdgeHashes = lists:all(fun({V, P}) ->
                                                     ProofHashes = merkle:proof_hashes(P),
                                                     not lists:member(merkle:hash_value(V), ProofHashes) andalso
                                                         not lists:member(RootHash, ProofHashes)
                                             end, ValuesAndProofs),
                    InvalidProofs = [ {V, P} || {V, P} <- ValuesAndProofs, element(1, P) == error ],
                    Verified = lists:all(fun({V, P}) -> merkle:verify_proof(merkle:hash_value(V), Tree, P) == ok end, ValuesAndProofs),
                    NoneVerified = lists:all(fun({V, P}) -> merkle:verify_proof(merkle:hash_value(V), NonTree, P) /= ok end, ValuesAndProofs),
                    NonValuesAndProofs = [ {V, merkle:gen_proof(merkle:hash_value(V), Tree)} || V <- NonValues ],
                    InvalidVerified = lists:all(fun({V, P}) -> merkle:verify_proof(merkle:hash_value(V), Tree, P) /= ok end, NonValuesAndProofs),
                    InvalidNonProofs = [ {V, P} || {V, P} <- NonValuesAndProofs, element(1, P) == error ],
                    UniqueLength = length(lists:usort(Values)),
                    ExpectedHeight = case UniqueLength of
                                         0 -> 0;
                                         N ->
                                             ceil(math:log2(N) + 1)
                                     end,
                    ?WHENFAIL(begin
                                  io:format(user, "Values:   ~p\n", [Values]),
                                  io:format(user, "NonValues:   ~p\n", [NonValues]),
                                  io:format(user, "Tree:     ~p\n", [Tree])
                              end,
                              conjunction([{count, eqc:equals(merkle:count(Tree), length(lists:usort(Values)))},
                                           {height, eqc:equals(merkle:height(Tree), ExpectedHeight)},
                                           {ordering, eqc:equals(merkle:values(Tree), UniqueValues)},
                                           {no_proofs_invalid, eqc:equals(InvalidProofs, [])},
                                           {no_edge_hashes, NoEdgeHashes},
                                           {all_proofs_verified, Verified},
                                           {no_non_proofs_verified, NoneVerified},
                                           {no_invalid_proofs_verified, InvalidVerified},
                                           {invalid_keys_have_no_proofs, eqc:equals(length(NonValues), length(InvalidNonProofs))}
                                          ]))
                catch
                    _:Err ->
                        io:format(user, "\nException: ~p\n", [Err]),
                        io:format(user, "Stacktrace: ~p\n", [erlang:get_stacktrace()]),
                        io:format(user, "Values:   ~p\n", [Values]),
                        io:format(user, "NonValues:   ~p\n", [NonValues]),
                        false
                end
            end).
