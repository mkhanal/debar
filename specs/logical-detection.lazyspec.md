> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Logical detection

What a scan reports for a file whose content a logical signature describes.

## A File Is Detected Under A Logical Signature's Name Exactly When Its Expression Holds

- Each subsignature's matches in the file are counted, a match at each distinct start once.
- `&` holds when both sides hold, `|` when either does.
- `=N`, `>N` and `<N` after a subsignature compare its count of matches.
- `=N`, `>N` and `<N` after parentheses compare the sum of the matches inside; `,M` after it also asks for at least `M` distinct subsignatures to have matched.
- A file for which the expression does not hold is not detected under the signature.
- The verdict of a detected file is a strong indicator.

## A Logical Expression Is Read Without Operator Precedence

- Without parentheses, an expression splits at its first `&` or `|`: `0|1&2` is `0|(1&2)`.
- Inside parentheses, it splits at the last: `(0&1|2)` is `(0&1)|2`.

## A Subsignature's Modifiers Match As The Signature Format Defines Them

- `i` matches letters in either case.
- `w` matches each byte followed by a zero byte, without widening gaps.
- `a` with `w` also matches the bytes as written.
- `f` matches only where no letter or digit is beside the match.

## A Potentially Unwanted Signature Is Reported Only When Potentially Unwanted Detection Is On

- Without the setting, a file matching a signature from a potentially unwanted database is not detected under it.
- With the setting, it is detected, and the verdict is potentially unwanted.
- With a category filter, only signatures whose category the filter admits are reported.

## A Logical Signature With A Regular Expression Is Detected When Its Trigger Holds And The Expression Matches

- The expression is matched only when its trigger, an expression over the earlier subsignatures, holds.
- With an offset of `n` or `EOF-n` and no `r` flag, the match must start there; with `,m`, it may start up to `m` bytes later.
- With the `e` flag and a `,m` shift, the whole match lies within those `m` bytes.
- With the `g` flag, every match that does not overlap the one before counts; without it, at most one does.
- `$` also matches before a final newline, `\s` matches a vertical tab, `.` matches anything but a newline, and the `i` flag folds ASCII letters only.

## Regular Expressions Are Not Matched In A File Larger Than The Regular-Expression Limit

- By default the limit is 104,857,600 bytes; `--largest-regular-expression-object BYTES` sets it, and 0 lifts it.
- In a larger file, every other subsignature is still matched and every logical signature still evaluated.

## A Byte Comparison Holds When The Bytes After Its Subsignature's Last Match Compare As It States

- The bytes are read at the start of the referenced subsignature's last match, moved by the comparison's offset.
- Binary bytes are read in the order the comparison names; text is read as hexadecimal or decimal.
- Every comparison given must hold.
- A read that starts at the first byte of the file, or runs past its end, does not hold.

## A Logical Signature Whose Regular Expression Holds A Backreference Or Lookaround Is Detected When It Matches

- A backreference, numbered or named, matches only what its group captured.
- A lookahead or lookbehind, positive or negative, tests without consuming.
- An atomic group never gives back what it matched.
- Such an expression that exhausts 100,000 steps from one start, or 2,000 open choices, does not match.
