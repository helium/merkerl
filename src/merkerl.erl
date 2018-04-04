%% @doc A module with a simple merkle tree implementation as described
%% in https://en.wikipedia.org/wiki/Merkle_tree implementation. This
%% module implements a immutable merkle tree. Once all the values are
%% available, it can construct a balanced tree for those values which
%% can then be used to access the leaf values, generate merkle proofs,
%% and verify generated proofs.

-module(merkerl).

-record(merkle, {
          root :: tree(),
          count = 0 :: non_neg_integer()
         }).

-record(leaf, {
          hash :: hash(),
          value :: any()
         }).

-record(empty, {
          hash = <<0:256>> :: hash()
         }).

-record(node, {
          hash :: hash(),
          height = 0 :: non_neg_integer(),
          left :: tree(),
          right :: tree()
         }).

-type hash() :: binary().
-opaque merkle() :: #merkle{}.
-opaque proof() :: [{left|right, hash()}].
-type tree() :: #leaf{} | #empty{} | #node{}.

-export_type([merkle/0, proof/0, hash/0]).
-export([new/2, root_hash/1, height/1, count/1, values/1, leaves/1, fold/3,
         gen_proof/2, verify_proof/3, proof_hashes/1, hash_value/1]).


%% @doc Construct a merkle tree given a list of values and a hash
%% function. The hash function is used to calculate the hash of the
%% leaf value. A simple one hash_value/1 is provided in this
%% module. The resulting merkle tree retains the order of the values
%% but duplicate values (as determined by the result of the hash
%% function) are skipped, so only the first found element counts.
-spec new([term()], fun((term()) -> hash())) -> merkle().
new(Values, HashFun) ->
    {_, UniqueLeaves} = lists:foldl(fun(Value, {SeenValues, Acc}) ->
                                            case sets:is_element(Value, SeenValues) of
                                                true ->
                                                    {SeenValues, Acc};
                                                false ->
                                                    L = to_leaf(Value, HashFun),
                                                    {sets:add_element(Value, SeenValues), [L | Acc]}
                                            end
                                    end, {sets:new(), []}, lists:reverse(Values)),
    #merkle{root=build_tree(UniqueLeaves), count=length(UniqueLeaves)}.

-spec build_tree([tree()]) -> tree().
build_tree([]) ->
    #empty{};
build_tree([Root]) ->
    Root;
build_tree(List) ->
    Level = lists:reverse(combine(List, [])),
    build_tree(Level).

combine([], Acc) ->
    Acc;
combine([X], Acc) ->
    [X | Acc];
combine([X, Y |T], Acc) ->
    combine(T, [to_tree(X, Y) | Acc]).

-spec mk_node(tree(), tree(), hash(), hash(), non_neg_integer()) -> tree().
mk_node(L, R, LHash, RHash, Height) ->
    Hash = crypto:hash(sha256, <<LHash/binary, RHash/binary>>),
    #node{left=L, right=R, height=Height+1, hash=Hash}.

-spec to_leaf(term(), fun((term()) -> hash())) -> tree().
to_leaf(Value, HashFun) ->
    #leaf{value=Value, hash=HashFun(Value)}.

-spec to_tree(tree(), tree()) -> tree().
to_tree(L=#leaf{hash=LHash}, R=#leaf{hash=RHash}) ->
    mk_node(L, R, LHash, RHash, 1);
to_tree(L=#node{hash=LHash, height=LHeight}, R=#leaf{hash=RHash}) ->
    mk_node(L, R, LHash, RHash, LHeight);
to_tree(L=#node{hash=LHash, height=LHeight}, R=#node{hash=RHash, height=RHeight}) ->
    mk_node(L, R, LHash, RHash, max(LHeight, RHeight)).

%% @doc Gets the root hash of the given merkle tree. This is a fast
%% operation since the hash was calculated on construction of the
%% tree.
-spec root_hash(merkle()) -> hash().
root_hash(#merkle{root=Tree}) ->
   tree_hash(Tree).

%% @doc Get the height of the given merkle tree. This is a fast
%% operation since the hash was calculated on construction of the
%% tree.
-spec height(merkle()) -> non_neg_integer().
height(#merkle{root=Tree}) ->
    tree_height(Tree).

%% @doc get the number of leaves int he merkle tree.
-spec count(merkle()) -> non_neg_integer().
count(#merkle{count=Count}) ->
    Count.

%% @doc Get the values of the merkle tree. This returns the values in
%% the same order as the list that was passed in on merkle
%% construction.
-spec values(merkle()) -> [term()].
values(M=#merkle{}) ->
    fold(fun({_Hash, Value}, Acc) -> [Value | Acc] end, [], M).

%% @doc Get a list of values and their hashes from the tree. The
%% resulting list retains the same order as the list that was passed
%% in on merkle construction.
-spec leaves(merkle()) -> [{hash(), term()}].
leaves(M=#merkle{}) ->
    fold(fun(Leaf, Acc) -> [Leaf | Acc] end, [], M).

%% @doc Fold over the leaves of the merkle tree. The given function
%% will take the a `{hash, value}' tuple, and a given accumulator to
%% fold over the merkle tree with and returns the resulting
%% accumulator.
-spec fold(FoldFun, Acc, tree() | merkle()) -> Acc when
      FoldFun :: fun(({hash(), term()}, Acc) -> Acc),
      Acc :: any().
fold(Fun, Acc, #merkle{root=Tree}) ->
    fold(Fun, Acc, Tree);
fold(Fun, Acc, #node{left=L, right=R}) ->
    RAcc = fold(Fun, Acc, R),
    fold(Fun, RAcc, L);
fold(Fun, Acc, #leaf{hash=Hash, value=Value}) ->
    Fun({Hash, Value}, Acc);
fold(_Fun, Acc, #empty{}) ->
    Acc.

-spec tree_hash(tree()) -> hash().
tree_hash(#node{hash=Hash}) ->
    Hash;
tree_hash(#leaf{hash=Hash}) ->
    Hash;
tree_hash(#empty{hash=Hash}) ->
    Hash.

-spec tree_height(tree()) -> non_neg_integer().
tree_height(#node{height=Height}) ->
    Height;
tree_height(#leaf{}) ->
    1;
tree_height(#empty{}) ->
    0.

%% @doc Generate a merkle proof for a given hash in the tree. Note
%% that the resulting proof does not include the value hash itself,
%% which saves space in the proof.
-spec gen_proof(any(), merkle()) ->  proof() | not_found.
gen_proof(ValueHash, #merkle{root=Tree}) ->
    gen_proof(ValueHash, Tree, []).

-spec gen_proof(hash(), tree() | merkle(), list()) -> proof() | {error, Reason} when
      Reason :: not_found
              | no_possible_proof.
gen_proof(_ValueHash, #empty{}, _Acc) ->
    {error, no_possible_proof};
gen_proof(ValueHash, #leaf{hash=ValueHash}, Acc) ->
    Acc;
gen_proof(_ValueHash, #leaf{}, _Acc) ->
    {error, not_found};
gen_proof(ValueHash, #node{left=#leaf{hash=ValueHash}, right=R}, Acc) ->
    [{left, tree_hash(R)} | Acc];
gen_proof(ValueHash, #node{left=L, right=#leaf{hash=ValueHash}}, Acc) ->
    [{right, tree_hash(L)} | Acc];
gen_proof(ValueHash, #node{left=L, right=R}, Acc) ->
    case gen_proof(ValueHash, L, Acc) of
        {error, Reason} -> case gen_proof(ValueHash, R, Acc) of
                               {error, Reason} -> {error, Reason};
                               Proof -> [{right, tree_hash(L)} | Proof]
                           end;
        Proof -> [{left, tree_hash(R)} | Proof]
    end.

%% @doc Verifies that a given hash of a value is in a given merkle
%% tree using the provided proof.
-spec verify_proof(hash(), merkle() | hash(), proof() | {error, any()}) -> ok | {error, Reason} when
      Reason :: root_hash_mismatch
              | invalid_proof.
verify_proof(_, _, {error, _}) ->
    {error, invalid_proof};
verify_proof(ValueHash, #merkle{root=Tree}, Proof) ->
    verify_proof(ValueHash, tree_hash(Tree), Proof);
verify_proof(ValueHash, RootHash, Proof) when is_binary(RootHash) ->
    ProofHash = verify_proof(ValueHash, Proof),
    case ProofHash == RootHash of
        true -> ok;
        false -> {error, root_hash_mismatch}
    end.

verify_proof(ValueHash, []) ->
    ValueHash;
verify_proof(ValueHash, [{left, RHash} | Tail]) ->
    LHash = verify_proof(ValueHash, Tail),
    hash_value(<<LHash/binary, RHash/binary>>);
verify_proof(ValueHash, [{right, LHash} | Tail]) ->
    RHash = verify_proof(ValueHash, Tail),
    hash_value(<<LHash/binary, RHash/binary>>).

%% @doc Get just the hashes from a given proof.
-spec proof_hashes(proof()) -> [hash()].
proof_hashes(Proof) ->
    [element(2, T) || T <- Proof].

%% @doc A commonly used hash value for merkle trees. This function
%% will SHA256 hash the given value when it is binary. A convenience
%% form detects non-binary forms and uses term_to_binary/1 to convert
%% other erlang terms to a binary form. It is not recommended to use
%% the non-binary form if the resulting trees or proofs are to be sent
%% over a network.
hash_value(Value) when is_binary(Value) ->
    crypto:hash(sha256, Value);
hash_value(Value) ->
    hash_value(term_to_binary(Value)).
