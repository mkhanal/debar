> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# File typing

The type a scan reports for a file, from the file-type database loaded with the other databases.

## A File Is Typed From Its First Bytes As The File-Type Database Says

- A file starting with a magic the database lists is reported as that magic's type; where two magics match, the one listed later wins.
- A file with no listed magic is reported as text or as binary data, by the bytes it holds.
- A pattern the database lists, found in the first 1,024 bytes of text or binary data, gives its type.

## Every Mark In A File's First Bytes Is Weighed In The Order It Is Found

- Each place in the first 1,024 bytes of text or binary data where a pattern the database lists is found counts again, so a type found again after another can take the type back.
- A pattern in parts that has given the type counts again only from a new first part.

## A File Typed As Never Scanned Has No Detection

- A file the database types as never scanned is reported with that type and no detection, even when a signature matches its bytes or hash.
