%% @doc A module with a skewed merkle tree implementation as described
%% in https://medium.com/codechain/skewed-merkle-tree-259b984acc0c.
%% This module implements a skewed merkle tree where value can be added/stacked via add/2,
%% the time and memory it takes to create is linearly proportional to the number of values.

-module(skewed).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([
    new/0, new/1, new/2,
    add/2, gen_proof/2, verify_proof/3,
    root_hash/1, height/1, count/1,
    hash_value/2,
    contains/2
]).

-record(leaf, {
    hash :: hash()
}).

-record(empty, {
    hash = <<0:256>> :: hash()
}).

-record(node, {
    hash :: hash(),
    height = 0 :: non_neg_integer(),
    left :: #node{} | #empty{},
    right :: leaf()
}).

-record(skewed, {
    root = #empty{} :: tree(),
    count = 0 :: non_neg_integer(),
    hash_function = fun hash_value/2 :: hash_function()
}).

-type hash() :: binary().
-type skewed() :: #skewed{}.
-type leaf() :: #leaf{}.
-type tree() :: #empty{} | #node{}.

-define(LEAF_PREFIX, 0).
-define(NODE_PREFIX, 1).

-type hash_function() :: fun((term(), 0 | 1) -> hash()).

-export_type([skewed/0, hash/0, hash_function/0]).

%% @doc
%% Create new empty skewed merkle tree.
%% @end
-spec new() -> skewed().
new() ->
    #skewed{}.

-spec new(hash() | hash_function()) -> skewed().
new(Hash) when is_binary(Hash) ->
    #skewed{root=#empty{hash=Hash}};
new(HashFunction) when is_function(HashFunction) ->
    #skewed{hash_function=HashFunction}.

-spec new(hash(), hash_function()) -> skewed().
new(Hash, HashFunction) ->
    #skewed{root=#empty{hash=Hash}, hash_function=HashFunction}.

%% @doc
%% Add/stack new value (leaf) on top and recalculate root hash.
%% @end
-spec add(any(), skewed()) -> skewed().
add(Value, #skewed{root=Tree, count=Count, hash_function=HashFun}=Skewed) ->
    Leaf = to_leaf(Value, HashFun),
    Node = to_node(Tree, Leaf, tree_hash(Tree), leaf_hash(Leaf), HashFun, Count),
    Skewed#skewed{root=Node, count=Count+1}.

%% @doc
%% Generate a proof that `Value' appears in `Tree' by returning the list of
%% required sibling hashes and the root hash of the tree.
%% @end
-spec gen_proof(any(), skewed()) -> not_found | [hash(),...].
gen_proof(_Value, #skewed{count=0}) ->
    not_found;
gen_proof(Value, #skewed{root=Tree, hash_function=HashFun}) ->
    Hash = HashFun(Value, ?LEAF_PREFIX),
    case contains(Tree, Hash, [tree_hash(Tree)]) of
        false -> not_found;
        Proof -> Proof
    end.


%% @doc
%% Verify will check that the HashToVerify is correctly in the tree with the provided,
%% in order, lists of hashes (proof) and compare it to the RootHash.
%% @end
-spec verify_proof(hash(), hash_function(), [hash(),...]) -> boolean().
verify_proof(HashToVerify, _HashFun, [RootHash]) ->
    HashToVerify == RootHash;
verify_proof(HashToVerify, HashFun, [FirstHash|Hashes]) ->
    RH = lists:last(Hashes),
    FirstEmpty = #empty{hash=FirstHash},
    Result = lists:foldl(
        fun(RootHash, Acc) when RootHash == RH ->
                ?MODULE:root_hash(Acc) == RootHash;
            (Hash, #skewed{root=Tree, count=Count}=Acc) ->
                Leaf = to_leaf(Hash),
                Node = to_node(Tree, Leaf, tree_hash(Tree), leaf_hash(Leaf), HashFun, Count),
                Acc#skewed{root=Node, count=Count+1}
        end,
        #skewed{root=FirstEmpty, count=0},
        [HashToVerify|Hashes]
    ),
    Result == true.

%% @doc
%% Gets the root hash of the given skewed tree. This is a fast
%% operation since the hash was calculated on construction of the tree.
%% @end
-spec root_hash(skewed()) -> hash().
root_hash(#skewed{root=Tree}) ->
   tree_hash(Tree).

%% @doc
%% Get the height of the given skewed tree. This is a fast operation
%% since the height was calculated on construction of the tree.
%% @end
-spec height(skewed()) -> non_neg_integer().
height(#skewed{root=Tree}) ->
    tree_height(Tree).

%% @doc
%% get the number of leaves int he skewed tree.
%% @end
-spec count(skewed()) -> non_neg_integer().
count(#skewed{count=Count}) ->
    Count.

%% @doc
%% A commonly used hash value for skewed trees. This function
%% will SHA256 hash the given value when it is binary. A convenience
%% form detects non-binary forms and uses term_to_binary/1 to convert
%% other erlang terms to a binary form. It is not recommended to use
%% the non-binary form if the resulting trees or proofs are to be sent
%% over a network.
%% @end
-spec hash_value(any(), 0 | 1) -> hash().
hash_value(Value, Prefix) when is_binary(Value) ->
    crypto:hash(sha256, <<Prefix:8/integer, Value/binary>>);
hash_value(Value, Prefix) ->
    hash_value(term_to_binary(Value), Prefix).

%% @doc
%% Check if the skewed tree contains a value.
%% @end
-spec contains(skewed() | tree(), any()) -> boolean().
contains(#skewed{count=0}, _Value) ->
    false;
contains(#skewed{root=Tree}, Value) ->
    Hash = hash_value(Value, ?LEAF_PREFIX),
    case contains(Tree, Hash, []) of
        false -> false;
        _ -> true
    end.

%%====================================================================
%% Internal functions
%%====================================================================

-spec contains(tree(), hash(), [hash()]) -> false | [hash(),...].
contains(#empty{}, _, _Acc) ->
    false;
contains(#node{right=#leaf{hash=Hash}, left=Left}, Hash, Acc) ->
    [tree_hash(Left)|Acc];
contains(#node{left=Left, right=#leaf{hash=RightHash}}, Hash, Acc) ->
    contains(Left, Hash, [RightHash|Acc]).

-spec to_leaf(hash()) -> leaf().
to_leaf(Hash) ->
    #leaf{hash=Hash}.

-spec to_leaf(term(), hash_function()) -> leaf().
to_leaf(Value, HashFun) ->
    #leaf{hash=HashFun(Value, ?LEAF_PREFIX)}.

-spec to_node(tree(), leaf(), hash(), hash(), hash_function(), non_neg_integer()) -> tree().
to_node(L, R, LHash, RHash, HashFun, Height) ->
    Hash = HashFun(<<LHash/binary, RHash/binary>>, ?NODE_PREFIX),
    #node{left=L, right=R, height=Height+1, hash=Hash}.

-spec leaf_hash(leaf()) -> hash().
leaf_hash(#leaf{hash=Hash}) ->
    Hash.

-spec tree_hash(tree()) -> hash().
tree_hash(#node{hash=Hash}) ->
    Hash;
tree_hash(#empty{hash=Hash}) ->
    Hash.

-spec tree_height(tree()) -> non_neg_integer().
tree_height(#node{height=Height}) ->
    Height;
tree_height(#empty{}) ->
    0.

%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

new_test() ->
    Tree = new(<<1,2,3>>),
    ?assertEqual(<<1,2,3>>, ?MODULE:root_hash(Tree)),
    ?assertEqual(0, ?MODULE:count(Tree)).

verify_test() ->
    HashFun = fun hash_value/2,
    Size = 5,
    Tree = lists:foldl(
        fun(Value, Acc) ->
            add(Value, Acc)
        end,
        new(),
        lists:seq(1, Size)
    ),
    RootHash = ?MODULE:root_hash(Tree),
    Value = 3,
    %% this is the hash of the node adjacent to the leaf with value 3 (`Value')
    Hash2 = <<253,49,101,79,133,255,101,251,21,117,172,62,98,57,87,84,34,25,155,89,71,139,184,212,1,255,127,234,83,163,195,155>>,
    ValueHashes = lists:foldr(fun(V, A) -> [HashFun(V, ?LEAF_PREFIX)|A] end, [], lists:seq(Value+1, Size)),
    ExpectedProof = [Hash2] ++ ValueHashes ++ [RootHash],
    ?assertEqual(ExpectedProof, gen_proof(Value, Tree)),
    ?assert(verify_proof(HashFun(Value, ?LEAF_PREFIX), HashFun, ExpectedProof)),
    ?assertNot(verify_proof(HashFun(Value, ?LEAF_PREFIX), HashFun, [RootHash])),
    ?assert(verify_proof(RootHash, HashFun, [RootHash])),
    ok.

proof_test() ->
    HashFun = fun hash_value/2,
    ?assertEqual(not_found, gen_proof(lol, new())),
    Size = 5,
    Tree = lists:foldl(
        fun(Value, Acc) ->
            add(Value, Acc)
        end,
        new(HashFun(7, ?LEAF_PREFIX)),
        lists:seq(1, Size)
    ),
    ?assertEqual(not_found, gen_proof(10, Tree)),
    ?assertNotEqual(not_found, gen_proof(2, Tree)),
    ?assertEqual(not_found, gen_proof(7, Tree)),
    ok.

contains_test() ->
    Size = 5,
    Tree = lists:foldl(
        fun(Value, Acc) ->
            add(Value, Acc)
        end,
        new(),
        lists:seq(1, Size)
    ),

    ?assertEqual(true, lists:all(fun(I) ->
                                         true == contains(Tree, I)
                                 end,
                                 lists:seq(1, Size))),

    ?assertEqual(true, lists:all(fun(I) ->
                                         false == contains(Tree, I)
                                 end,
                                 lists:seq(-10, 0))),

    %% Check that empty tree contains no value
    Tree2 = new(),
    ?assertEqual(true, lists:all(fun(I) ->
                                         false == contains(Tree2, I)
                                 end,
                                 lists:seq(-1, 10))),

    ok.

height_test() ->
    Tree0 = new(),
    ?assertEqual(0, height(Tree0)),
    Tree1 = lists:foldl(
        fun(Value, Acc) ->
            add(Value, Acc)
        end,
        new(),
        lists:seq(1, 10)
    ),
    io:format("Tree1: ~p~n", [Tree1]),
    ?assertEqual(10, height(Tree1)),
    ?assertEqual(0, tree_height(#empty{hash= <<>>})),
    ok.

construct_test() ->
    Tree0 = new(crypto:hash(sha256, "yolo")),
    ?assertEqual(0, height(Tree0)),
    Tree1 = add("hello", Tree0),
    ?assertEqual(1, height(Tree1)),
    Tree2 = add("namaste", Tree1),
    ?assertEqual(2, height(Tree2)),
    ok.

count_test() ->
    Tree0 = new(),
    ?assertEqual(0, count(Tree0)),
    Tree1 = lists:foldl(
        fun(Value, Acc) ->
            add(Value, Acc)
        end,
        new(),
        lists:seq(1, 10)
    ),
    ?assertEqual(10, count(Tree1)),
    ok.

-endif.
