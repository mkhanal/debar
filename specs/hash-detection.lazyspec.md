> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Hash detection

What a scan reports for a file whose hash a database lists.

## A File Whose MD5 Is Listed Is Detected Under The Signature's Name

- The detection carries the name the database gives the signature.
- The verdict is a strong indicator.

## A File Whose SHA-256 Is Listed Is Detected Under The Signature's Name

- The detection carries the name the database gives the signature.

## A Listed False-Positive Hash Suppresses The Detection

- A file detected by its hash is reported with no detection when a false-positive list holds its hash.
- The verdict is trusted.

## A Signature From A File Outside A Signed Container Is Reported With .UNOFFICIAL After Its Name

- A signature from a loose database file is reported as its name followed by `.UNOFFICIAL`.
- A signature from inside a signed container is reported under its name alone.
