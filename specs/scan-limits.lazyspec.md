> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Scan limits

What a scan leaves unscanned because of a size, and what it reports for it.

## A File Of Five Bytes Or Less Is Never Scanned

- It has no detection and no type, and the verdict is nothing found.
- A file of six bytes holding the same body is detected.

## A File Larger Than The File-Size Limit Is Not Scanned

- With the default limit of 100 MiB, a larger file has no detection and no type, and the verdict is nothing found.
- A file of exactly the limit is scanned.
