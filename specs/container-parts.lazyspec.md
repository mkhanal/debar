> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Container parts

How the parts a format module finds in a container (an archive's members, a document's streams, a normalised view of its text) are scanned. Each rule holds whatever the container's format, except the order of its parts and its own bytes, which its format sets. Proved with a test-only container that can take either order.

## Each Part Of A Container Is Scanned Whole Before The Next Part Is Read

- Asked for every detection, the detections in a container's parts are reported in the order the container holds them.
- Asked for one, a detection in a part ends the scan, and no later part is read.

## A Container's Parts Are Scanned Before Or After Its Own Bytes, As Its Format Orders Them

- A format that opens its container first (an archive, an OLE2 document, a mail message, a web page) has a part's detection reported before one in the container's own bytes, under every detection.
- Asked for one, a detection in such a container's part ends the scan before the container's own bytes are matched.
- A format that matches its container's own bytes first (a PDF document, plain text) has a detection in the container's own bytes reported before a part's, under every detection.
- Asked for one, a detection in such a container's own bytes ends the scan before any part is read.

## A Part Is An Object One Level Deeper Than Its Container, Under The Same Limits

- A part is typed from its own bytes and its detections are reported on it.
- A part found inside a part is one level deeper again, and a part beyond the recursion limit is not scanned.
- Every scanned part counts against the file-count and scan-size limits.
- A part too large for what remains of the scan-size limit is skipped, and later parts are still scanned.

## A Damaged Container Keeps What Its Earlier Parts Found, And Its Own Bytes Are Still Matched

- A container damaged after its first part reports that part's detection and the detection in its own bytes.

## A Normalised View Is Matched As Its Kind, Uses A Level, And Is Never Counted

- A detection in a view is reported on the view.
- A view does not count against the file-count limit.
- A view beyond the recursion limit is not scanned.

## A Container Entry Is Tested Against Container Signatures Before Its Part Is Scanned

- A container signature matching an entry is reported on the container.
- Asked for one detection, it ends the scan before the entry's part is read.

## An Archive Found Inside Another File Spans Only The Length Its Header Gives

- The archive is an object of the length its header check measures.
- A second archive inside that length is not an object of its own; one after it is.
- An archive whose header check fails is not an object.

## Scanning A Container Holds At Most 32 MiB Of Memory, However Large Its Parts Decode To

- It is measured as the peak heap while scanning a container nested three deep, each level decoding to a part of 24 MiB, less the heap held before the scan.
- Every part is scanned, and a detection in the innermost is reported.

## A Container's Facts Are Reported With The Object They Describe, Only When Asked For

- With facts asked for, a fact a format module finds is reported on the object it describes.
- Without them, no fact is reported.
- A damaged container is reported as broken where the damage starts.
