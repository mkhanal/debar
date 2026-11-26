> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Scan speed

How fast Debar scans, with every pinned database in its image and default settings.

## Debar Scans At Least Twice As Fast As The Reference Scanner

- For each kind of content in the standard benchmark corpus (system files, text, web pages, random binary data, PDF, OLE2 and tar), Debar scans at most the instructions per MiB that would run at twice the reference scanner's measured single-threaded rate on that kind.
- The instructions are counted on fixed slices of each kind, generated the same way on every run, and system files from the toolchain image.
- Wall-clock rates on the whole corpus are measured and recorded; they do not gate a change.
