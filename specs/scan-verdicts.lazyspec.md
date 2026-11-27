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

## Binary Data Is Matched Twice, As Itself And As Other Data

- With every match, a generic signature or a listed hash matching a file of binary data is reported twice: once from the file's own pass, once from its pass as other data.
- A signature for other data is detected on a file of binary data, and not on text.
- Compiled Python and AI models are matched twice in the same way.

## A Page Typed As HTML From Its First Bytes Is Never Detected By The Hash Of Its Own Bytes

- A file the file-type database types as HTML from its first bytes is reported with no detection when a hash signature lists it.

## A Raw-Only Scan Matches Each Object Once, Against The Signatures For Any Kind

- Asked for a raw-only scan, a file of binary data is reported with a generic signature and a listed hash once each, and a signature for other data is not detected.
- A file typed as HTML from its first bytes is detected by the hash of its own bytes.
- The file is still reported with its type.

## Every File Gets The Same Verdict And Detections However Many Files Are Scanned At Once

- Scanning many files on any number of threads gives each file the verdict and detections, in the same order, that scanning the files one at a time gives it.
- The results are reported in the order of the files, whatever order their scans finish in.
