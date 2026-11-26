> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Pattern detection

What a scan reports for a file holding the bytes an extended signature describes.

## A File Holding An Extended Signature's Body Where Its Offset Allows Is Detected Under The Signature's Name

- A body with offset `*` is detected wherever it starts.
- A body with offset `n` is detected only when it starts at byte `n`; with `n,m`, when it starts anywhere from `n` to `n+m`.
- A body with offset `EOF-n` is detected only when it starts `n` bytes before the end of the file.
- Wildcards, gaps and alternatives in the body match as the signature format defines them.
- The verdict is a strong indicator.

## A Body Is Detected Wherever It Lies In A Large File

- A body spanning a 128 KiB boundary of the file is detected.
- A body whose parts lie hundreds of kilobytes apart is detected.

## A Signature For One Kind Of Object Is Not Reported On Another Kind

- An extended signature for one kind of object, such as executables or web pages, is detected in a file of that kind.
- The same bytes in a file of another kind are not detected under it.

## A Body Whose Parts Are A Bounded Distance Apart Is Missed Where The Reference Scanner Misses It

- A body of two parts at most a bounded distance apart is detected when its first part occurs once before the second.
- It is not detected when eight or more occurrences of its first part, too close to the second, follow the one at the right distance.
