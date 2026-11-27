> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# PDF documents

What a scan finds inside a PDF document, as a user of the supported signature format observes it.

## A PDF's Streams Are Scanned As Their Decoded Bytes

- Each stream with a `FlateDecode`, `ASCIIHexDecode` or `ASCII85Decode` filter is an object one level below the document, holding the stream decoded by each of its filters in turn, `LZWDecode` and `RunLengthDecode` among them, typed from its bytes.
- A stream with no filter is an object holding the stream's bytes.
- A stream whose filters are only `LZWDecode` or `RunLengthDecode` is not an object.
- A stream whose first filter cannot be decoded is an object holding the stream's bytes as stored.
- An image stream that is not a JPEG is not an object.

## A PDF's Scripts Are Scanned As Objects Of Their Own

- Each `/JS` string following a `/JavaScript` name in an object that is not a stream is written out, the strings of one object together, and the result is an object one level below the document.

## Objects Inside A PDF Object Stream Are Scanned Like Any Other Object

- The objects an object stream holds are found in its decoded bytes, and a script among them is an object one level below the document.

## A PDF Page's Text Is Scanned As An Object Of Its Own

- The text inside the parentheses of a page's text arrays, lower-cased with each run of white space one space, is an object one level below the document, after the page's content stream.

## A Signature Naming A PDF As Its Container Matches What Is Extracted From It

- A logical signature with `Container:CL_TYPE_PDF` matches an object extracted from a PDF, and the normalised text of such an object.

## A PDF Name Written With Escapes Is Reported As An Obfuscated Name

- A document holding a common name written with `#` escapes, such as `/J#61vaScript`, is reported as `Heuristics.PDF.ObfuscatedNameObject`.

## An Object Refused By A Limit Ends The Scan Of A PDF's Objects

- When an object extracted whole from a PDF is refused by the scan-size limit, no later object of the document is scanned.
