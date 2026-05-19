#!/usr/bin/env escript

%% escript entry point. Args is the list of command-line arguments as strings.
%% The two clauses use pattern matching: the first matches an empty list,
%% the second matches any non-empty list bound to Files.
main([]) ->
    io:format("usage: wc.escript <file> [file ...]~n"),
    halt(1);  %% halt/1 exits the VM with a non-zero code to signal failure
main(Files) ->
    %% List comprehension: apply stat/1 to every filename, collect results.
    Stats = [stat(F) || F <- Files],
    %% Print one output row per file.
    [print_row(S) || S <- Stats],
    %% Only show a totals row when more than one file was given.
    case Stats of
        [_] -> ok;
        _   -> print_totals(Stats)
    end.

%% Read a file and return {Filename, Lines, Words, Bytes}.
%% file:read_file/1 returns {ok, Binary} or {error, Reason}.
stat(File) ->
    case file:read_file(File) of
        {ok, Bin} ->
            %% Split on newlines globally; subtract 1 because splitting
            %% "a\nb\n" yields ["a","b",""] — one extra empty segment.
            Lines = length(binary:split(Bin, <<"\n">>, [global])) - 1,
            %% string:lexemes splits on any whitespace, skipping empty tokens.
            Words = length(string:lexemes(binary_to_list(Bin), " \t\n\r")),
            Bytes = byte_size(Bin),
            {File, Lines, Words, Bytes};
        {error, Reason} ->
            io:format("wc: ~s: ~s~n", [File, file:format_error(Reason)]),
            {File, 0, 0, 0}
    end.

%% ~8w right-aligns an integer in a field of width 8; ~s prints a string.
print_row({File, Lines, Words, Bytes}) ->
    io:format("~8w ~8w ~8w  ~s~n", [Lines, Words, Bytes, File]).

%% lists:foldl walks the Stats list accumulating running totals.
%% The fun receives each {_, L, W, B} tuple and the current accumulator {AL, AW, AB}.
print_totals(Stats) ->
    {TL, TW, TB} = lists:foldl(
        fun({_, L, W, B}, {AL, AW, AB}) -> {AL + L, AW + W, AB + B} end,
        {0, 0, 0},  %% initial accumulator
        Stats
    ),
    io:format("~8w ~8w ~8w  total~n", [TL, TW, TB]).
