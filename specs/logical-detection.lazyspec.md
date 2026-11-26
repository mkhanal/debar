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
