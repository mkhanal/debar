> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Signature databases

What becomes of the databases a user loads: every line accounted for, and the image they compile to.

## Every Hash Signature Line In The Pinned Databases Is Accounted For In The Image

- Compiling the pinned databases accounts for every line of every file in them, file by file.
- Each hash signature line is compiled, left out because its functionality-level range excludes the reference scanner's level, dropped by an ignore list, or shadowed by a line with the same hash and size whose name is reported instead. None is unsupported.
- The image holds one entry for each compiled hash signature line.

## The Same Databases Always Compile To The Same Image, Byte For Byte

- Compiling the same databases twice gives identical images.
- The images compiled on amd64 and on arm64 are identical.

## Every Extended Signature Line In The Pinned Databases Is Accounted For In The Image

- Every extended signature line has one outcome: compiled, outside the functionality level, ignored, a comment, its target not loaded, or never reporting.
- Every loaded line is compiled, whatever its target and offset. None is unsupported.
- The image holds one pattern signature for each compiled line.

## Every File-Type Line In The Pinned Databases Is Accounted For In The Image

- Every line of the file-type database has one outcome: compiled, outside the functionality level, a comment, or of a kind the signature format does not use.
- Every loaded line is compiled.
- The image holds one type magic for each compiled magic line and one type recognition signature for each compiled recognition line.

## A Malformed Extended Signature Line Fails The Compile

- A line with too few or too many fields, an empty name, a malformed level, target, offset or body fails the compile, naming the file and line.
- No image is written.

## Every Logical Signature Line In The Pinned Databases Is Accounted For In The Image

- Every logical signature line has one outcome: compiled, outside the functionality level, ignored, a comment, its target not loaded, not loaded for an unknown attribute or type, or not yet compiled.
- A line is not yet compiled only when it holds a regular-expression, byte-comparison, image fuzzy hash or macro subsignature.
- Every other loaded line is compiled.
- The image holds one logical signature for each compiled line.

## A Malformed Logical Signature Line Fails The Compile

- A line with too few fields, a malformed expression, a subsignature count that disagrees with the expression, a malformed attribute, no target or a malformed subsignature fails the compile, naming the file and line.
- No image is written.
