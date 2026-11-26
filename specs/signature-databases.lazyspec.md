> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Signature databases

What becomes of the databases a user loads: every line accounted for, and the image they compile to.

## Every Hash Signature Line In The Pinned Databases Is Accounted For In The Image

- Compiling the pinned databases accounts for every line of every file in them, file by file.
- Each hash signature line is compiled, left out because its functionality-level range excludes the reference scanner's level, or dropped by an ignore list. None is unsupported.
- The image holds one entry for each compiled hash signature line.

## The Same Databases Always Compile To The Same Image, Byte For Byte

- Compiling the same databases twice gives identical images.
- The images compiled on amd64 and on arm64 are identical.
