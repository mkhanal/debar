> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Scan verdicts

Which of a file's detections a scan reports, in what order, and the verdict it gives.

## The First Strong Detection Ends The Scan Unless Every Match Is Asked For

- Without every match, a file matching two signatures in different parts of it is reported under the one found first, and nothing after it.
- With every match, it is reported under both, in the order they were found.
- Either way the verdict is a strong indicator.

## A Potentially Unwanted Detection Is Reported Only When Nothing Strong Is Found

- A potentially unwanted detection never ends the scan.
- Without every match, a file with a strong detection is reported under that alone, even when a potentially unwanted one was found first.
- Without every match, a file with only potentially unwanted detections is reported under the last one found, and the verdict is potentially unwanted.

## With Every Match, Potentially Unwanted Detections Are Reported After Every Strong One

- Every strong detection is reported first, in the order found, then every potentially unwanted one, in the order found.

## With Heuristic Precedence, A Potentially Unwanted Detection Is Strong

- It ends the scan as a strong detection does, and is reported where it was found.
- The verdict is a strong indicator.

## A File Whose Hash Is Listed As A False Positive Is Trusted, Whatever Detected It

- A file detected by a pattern signature is reported with no detection when a false-positive list holds its hash, even when no hash signature is loaded.
- The verdict is trusted.
