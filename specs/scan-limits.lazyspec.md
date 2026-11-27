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

## A File Up To The File-Size Limit Is Scanned To Its End

- A file of exactly 100 MiB has its regular expressions, those needing backtracking among them, matched over the whole file, up to its last byte and across every point inside it.
- Asked for every detection, it reports the set of names the reference scanner reports for the same file and databases; asked for one, it reports one of them.
- The scan completes, and the verdict is reported.

## A File Is Scanned To Its End However Many Signatures It Triggers That Cannot Report In It

- A file of 17 MiB holding the trigger of 400 logical signatures with a regular expression, each with a container condition the file does not meet, completes with its verdict and the detection at its last bytes.
- Those signatures add nothing to the work the scan time limit counts.

## A File Is Scanned To Its End However Many Regular Expressions It Triggers

- With the default limits, a file of 100 MiB holding at its last bytes a match for each of 200 logical signatures' regular expressions, each searched over the whole file, reports all 200 asked for every detection, and the scan completes.
- The scan takes less than a tenth of the default scan time limit's work.
- Scanning it holds at most 32 MiB of memory.

## An Object Deeper Than The Recursion Limit Is Not Scanned

- With a recursion limit of N, the deepest object scanned is at level N − 1, the top-level file being level 0.
- An object not scanned for it has no detection; the file holding it is still scanned.

## The Top-Level File Counts Against The File-Count Limit

- With a file-count limit of 1, no object inside the file is scanned; with 2, the first one is.

## An Object Too Large For What Remains Of The Scan-Size Limit Is Skipped, And Later Ones Are Still Scanned

- Every scanned object counts its whole length against the scan-size limit, the top-level file included.

## A File Many Times Larger Than The Scan-Size Limit Is Still Reported

- With a scan-size limit of 200,000 bytes and a file-size limit of 2,000,000 bytes, a file of 3 MiB is reported with its size and SHA-256, no detection and no type, and the verdict nothing found.

## At Most One Limit Alert Is Reported, And Only When Asked For

- With limit alerts asked for, the first limit reached is reported as a potentially unwanted detection named for that limit.
- A second limit reached in the same scan reports nothing more.
- Without limit alerts asked for, a limit reached reports nothing.

## A Scan's Time Limit Gives The Same Verdict At Any Machine Speed

- The scan time limit is counted in the work a scan does, never on a clock.
- The same file, databases and settings give the same report on every run, however fast or busy the machine.

## A Scan That Would Exceed Its Time Limit Stops, Keeps What It Found, And Alerts Only When Asked

- The whole scan stops where its time limit is reached; nothing after that point is scanned.
- Detections found before it stopped are reported, and the scan completes with its verdict.
- With limit alerts asked for, it is reported as a potentially unwanted detection named for the scan time limit; without, it reports nothing more.
- A scan time limit of 0 switches it off.
