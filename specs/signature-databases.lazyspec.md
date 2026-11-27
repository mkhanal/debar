> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Signature databases

What becomes of the databases a user loads: every line accounted for, and the image they compile to.

## Every Line Of Every Pinned Database File Is Accounted For And None Is Left Uncompiled

- Compiling the pinned databases accounts for every line of every file in them, file by file, with one outcome per line.
- No line of any kind of file is left not yet compiled.

## Every Hash Signature Line In The Pinned Databases Is Accounted For In The Image

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

- Every logical signature line has one outcome: compiled, outside the functionality level, ignored, a comment, its target not loaded, or not loaded for an unknown attribute or type.
- Every loaded line is compiled, its regular-expression, byte-comparison and image fuzzy hash subsignatures included, and regular expressions with backreferences, lookaround or atomic groups among them.
- The image holds one logical signature for each compiled line.

## A Malformed Logical Signature Line Fails The Compile

- A line with too few fields, a malformed expression, a subsignature count that disagrees with the expression, a malformed attribute, no target or a malformed subsignature fails the compile, naming the file and line.
- No image is written.

## Every Container Signature Line In The Pinned Databases Is Accounted For In The Image

- Every container signature line has one outcome: compiled, outside the functionality level, ignored, or a comment.
- Every loaded line is compiled. None is unsupported.
- The image holds one container signature for each compiled line.

## A Malformed Container Signature Line Fails The Compile

- A line with fewer than 10 or more than 12 fields, an unknown container type, a malformed size, position, encrypted flag, functionality level or entry name expression fails the compile, naming the file and line.
- No image is written.

## Every Certificate Rule, Icon Signature And URL Rule In The Pinned Databases Is Compiled Into The Image

- All 30 certificate rules compile, 8 trusting and 22 blocking a certificate.
- All 222 icon signatures compile, into 22 groups of the first kind and 19 of the second.
- All 263 monitored and 185 allowed URL rules compile.
- The image holds one entry for each compiled line.

## Every Engine Switch In The Pinned Databases Is Evaluated At The Functionality Level

- A switch line takes effect only when the functionality level lies within its range.
- None of the 21 pinned switch lines takes effect, so the image records every engine feature at its default.

## Every Signature Program In The Pinned Databases Is Verified And Compiled Into The Image

- The 82 programs whose level range holds the functionality level pass every load-time check and compile; the other 3 are left out.
- A program's trigger compiles as a logical signature that triggers the program instead of reporting a detection.
- Each program records whether it came from a signed container.

## Every Pinned Database Is Verified By Its Digital Signature

- Each pinned database is recorded as verified by its detached signature.
- Each member it loads matches the size and SHA-256 its signed index lists.

## A Database Whose Digital Signature Does Not Verify Is Refused

- A signed container changed after signing fails the compile, naming the file, whether or not its detached signature is beside it.
- No image is written.

## A Malformed Certificate, Icon, URL-Rule Or Switch Line, Or A Malformed Signature Program, Fails The Compile

- The compile fails, naming the file and, for a line, its number.
- No image is written.

## A Compiled Image Is Written So That No One May Change It In Place

- The compiler writes the image under another name and moves it into place whole.
- The image it leaves is readable by every user and writable by none.

## An Image Someone Else Could Change While Debar Uses It Is Refused

- Debar refuses an image that any user may write, naming the image, and scans nothing.
- Debar refuses an image owned by a user other than the one it runs as or the administrator, naming the image, and scans nothing.
