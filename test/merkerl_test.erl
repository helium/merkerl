-module(merkerl_test).

-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    %% Construct a tree
    Values = ["foo", "bar", "baz", "dog", "cat", "bear", "plant"],
    M = merkerl:new(Values, fun merkerl:hash_value/1),
    %% Verify leaf count and tree height
    ?assertEqual(7, merkerl:count(M)),
    ?assertEqual(4, merkerl:height(M)),

    %% Verify values
    ?assertEqual(Values, merkerl:values(M)),
    %% Verify leaves
    ?assertEqual(lists:zip(lists:map(fun merkerl:hash_value/1, Values), Values),
                 merkerl:leaves(M)),

    %% Generate a proof
    ValueHash = merkerl:hash_value("bar"),
    MP = merkerl:gen_proof(ValueHash, M),

    ?assertEqual(3, length(merkerl:proof_hashes(MP))),

    %% And verify it
    ?assertEqual(ok, merkerl:verify_proof(ValueHash, M, MP)),
    %% Will error on bad value
    BadValueHash = merkerl:hash_value("bah"),
    ?assertEqual({error, root_hash_mismatch},
                 merkerl:verify_proof(BadValueHash, M, MP)),

    %% Will not generate proof for non-existing value
    ?assertEqual({error, not_found},
                 merkerl:gen_proof(BadValueHash, M)),
    %% or generate a proof based on a previous error condition,
    ?assertEqual({error, invalid_proof},
                merkerl:verify_proof(BadValueHash, M, merkerl:gen_proof(BadValueHash, M))),

    ok.

empty_test() ->
    M = merkerl:new([], fun merkerl:hash_value/1),
    %% Verify leaf count and tree height
    ?assertEqual(0, merkerl:count(M)),
    ?assertEqual(0, merkerl:height(M)),
    ?assertEqual(<<0:256>>, merkerl:root_hash(M)),
    ?assertEqual([], merkerl:values(M)),
    ?assertEqual([], merkerl:leaves(M)),

    % Can not generate proofs
    ?assertEqual({error, no_possible_proof},
                 merkerl:gen_proof(merkerl:hash_value("bar"), M)),

    ok.

near_empty_test() ->
    M = merkerl:new(["foo"], fun merkerl:hash_value/1),
    %% Verify leaf count and tree height
    ?assertEqual(1, merkerl:count(M)),
    ?assertEqual(1, merkerl:height(M)),

    % Can generate proof
    ValueHash = merkerl:hash_value("foo"),
    MP = merkerl:gen_proof(ValueHash, M),

    % Check proof hashes
    ?assertEqual(0, length(merkerl:proof_hashes(MP))),
    %% And verify it
    ?assertEqual(ok, merkerl:verify_proof(ValueHash, M, MP)),

    ok.


dedupe_test() ->
    %% Removes duplicates
    ?assertEqual(1, merkerl:count(merkerl:new(["bar", "bar"], fun merkerl:hash_value/1))),

    ok.
