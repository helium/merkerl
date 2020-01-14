%% @doc A module with a skewed merkle tree implementation as described
%% in https://medium.com/codechain/skewed-merkle-tree-259b984acc0c.
%% This module implements a skewed merkle tree where value can be added/stacked via add/3,
%% the time and memory it takes to create is linearly proportional to the number of values.

-module(skewed).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([
    new/0, add/3, verify/3,
    root_hash/1, height/1, count/1,
    hash_value/1
]).

-record(skewed, {
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
-type skewed() :: #skewed{}.
-type leaf() :: #leaf{}.
-type tree() :: #leaf{} | #empty{} | #node{}.

-export_type([skewed/0, hash/0]).

%% @doc
%% Create new empty skewed merkle tree.
%% @end
-spec new() -> skewed().
new() ->
    #skewed{root=#empty{}, count=0}.

%% @doc
%% Add/stack new value (leaf) on top and recalculate root hash.
%% @end
-spec add(any(), function(), skewed()) -> skewed().
add(Value, HashFun, #skewed{root=Tree, count=Count}=Skewed) ->
    Leaf = to_leaf(Value, HashFun),
    Node = to_node(Tree, Leaf, tree_hash(Tree), tree_hash(Leaf), Count),
    Skewed#skewed{root=Node, count=Count+1}.

%% @doc
%% Verify will check that the HashToVerify is correctly in the tree with the provided,
%% in order, lists of hashes (proof) and compare it to the RootHash.
%% @end
-spec verify(hash(), [hash()], hash()) -> boolean().
verify(HashToVerify, [], RootHash) ->
    HashToVerify == RootHash;
verify(HashToVerify, [FirstHash|Hashes], RootHash) ->
    FirstLeaf = #leaf{hash=FirstHash, value=undefined},
    Skewed = lists:foldl(
        fun(Hash, #skewed{root=Tree, count=Count}=Acc) ->
            Leaf = to_leaf(Hash),
            Node = to_node(Tree, Leaf, tree_hash(Tree), tree_hash(Leaf), Count),
            Acc#skewed{root=Node, count=Count+1}
        end,
        #skewed{root=FirstLeaf, count=0},
        [HashToVerify|Hashes]
    ),
    ?MODULE:root_hash(Skewed) == RootHash.

%% @doc
%% Gets the root hash of the given skewed tree. This is a fast
%% operation since the hash was calculated on construction of the tree.
%% @end
-spec root_hash(skewed()) -> hash().
root_hash(#skewed{root=Tree}) ->
   tree_hash(Tree).

%% @doc
%% Get the height of the given skewed tree. This is a fast operation
%% since the hash was calculated on construction of the tree.
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
-spec hash_value(any()) -> hash().
hash_value(Value) when is_binary(Value) ->
    crypto:hash(sha256, Value);
hash_value(Value) ->
    hash_value(term_to_binary(Value)).

%%====================================================================
%% Internal functions
%%====================================================================

-spec to_leaf(hash()) -> leaf().
to_leaf(Hash) ->
    #leaf{hash=Hash, value=undefined}.

-spec to_leaf(term(), fun((term()) -> hash())) -> leaf().
to_leaf(Value, HashFun) ->
    #leaf{value=Value, hash=HashFun(Value)}.

-spec to_node(tree(), tree(), hash(), hash(), non_neg_integer()) -> tree().
to_node(L, R, LHash, RHash, Height) ->
    Hash = crypto:hash(sha256, <<LHash/binary, RHash/binary>>),
    #node{left=L, right=R, height=Height+1, hash=Hash}.

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

%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

verify_test() ->
    HashFun = fun hash_value/1,
    Size = 5,
    Tree = lists:foldl(
        fun(Value, Acc) ->
            add(Value, HashFun, Acc)
        end,
        new(),
        lists:seq(1, Size)
    ),
    RootHash = ?MODULE:root_hash(Tree),
    Value = 3,
    Hash2 = <<55,252,129,255,194,115,98,103,168,132,199,77,143,180,26,174,29,219,145,126,179,56,47,160,125,10,249,248,75,49,96,253>>,
    ValueHashes = lists:foldr(fun(V, A) -> [HashFun(V)|A] end, [], lists:seq(Value+1, Size)),
    ?assert(verify(HashFun(Value), [Hash2] ++ ValueHashes, RootHash)),
    ?assertNot(verify(HashFun(Value), [], RootHash)),
    ?assert(verify(RootHash, [], RootHash)),
    ok.

height_test() ->
    HashFun = fun hash_value/1,
    Tree0 = new(),
    ?assertEqual(0, height(Tree0)),
    Tree1 = lists:foldl(
        fun(Value, Acc) ->
            add(Value, HashFun, Acc)
        end,
        new(),
        lists:seq(1, 10)
    ),
    ?assertEqual(10, height(Tree1)),
    ok.

count_test() ->
    HashFun = fun hash_value/1,
    Tree0 = new(),
    ?assertEqual(0, count(Tree0)),
    Tree1 = lists:foldl(
        fun(Value, Acc) ->
            add(Value, HashFun, Acc)
        end,
        new(),
        lists:seq(1, 10)
    ),
    ?assertEqual(10, count(Tree1)),
    ok.

-endif.