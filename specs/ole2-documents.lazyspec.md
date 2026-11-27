> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# OLE2 documents

What a scan finds inside an OLE2 compound file (a legacy Word, Excel or PowerPoint document, or a `vbaProject.bin`), as a user of the supported signature format observes it.

## An OLE2 Document's Streams Are Scanned As Objects Of Their Own

- Each stream of more than five bytes is an object one level below the document, whatever storage holds it, typed from its bytes.
- Its bytes are the stream's sectors, or mini-stream sectors, cut to its declared size.
- A detection in a stream is reported on the stream, and an OLE2 stream holding an OLE2 document is opened in turn.

## A Compressed OLE2 Stream Is Scanned As Its Inflated Bytes

- A stream whose bytes 4 and 5 are `78 9c` is not an object itself: the zlib data from byte 4 is inflated and the result is the object.
- A stream that inflates to nothing yields no object.

## A Word, PowerPoint Or Macro Document Scans A Stream Once More For Each Storage Holding It

- In a document holding a `WordDocument`, `PowerPoint Document`, `_VBA_PROJECT` or OLE1 native stream, or a workbook with a macro sheet, a stream inside `k` nested storages is scanned `k + 1` times.
- In any other document each stream is scanned once.

## A Loop In An OLE2 Directory Ends The Walk

- The directory is walked entry, child, right sibling, left sibling.
- Reaching an entry a second time ends the walk; streams not yet reached are not scanned.

## A Damaged OLE2 Stream Yields The Bytes Its Chain Still Holds

- A chain that leaves the file, loops, or ends early gives the stream the whole sectors read until then.
- A last sector cut short by the end of the file is filled with zero bytes up to the declared size.

## OLE2 Storages Nested Beyond The Recursion Limit End The Walk

- A storage deeper than the recursion limit ends the walk of the whole document, and the limit is reported when limit alerts are asked for.

## An OLE2 Document With An Invalid Header Is Matched On Its Own Bytes Only

- A sector shift outside 6 to 28, or a mini-sector shift of 0 or above the sector shift, leaves every stream unscanned.
