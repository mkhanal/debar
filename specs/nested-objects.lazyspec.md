> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Nested objects

Which objects a scan finds inside a file, or makes of it again as another kind, and how they are scanned.

## An Archive Found Inside Another File Is Scanned As An Object Of Its Own

- A self-extracting archive the file-type database finds after the start of a file is an object one level deeper, typed as the archive, from there to the file's end.
- A ZIP found there is instead an object of the one local header and data starting there.
- Its own detections are reported on it.
- An archive found at the very start, or in a file of its own archive kind, is not a separate object.
- An object of five bytes or less is never made.

## An Object Found Inside Another Is Not Searched For Objects Of Its Own

- An archive found inside a file holds no object found the same way, though the file's later archives are each still an object.

## A Handler Type Scans The File Again As That Kind

- A logical signature with a handler type that holds makes the file an object again, one level deeper, of that kind, with the same bytes.
- The signature is reported on that object, not on the file.

## A Raw-Only Scan Finds No Object Inside Another, Yet A Handler Type Still Scans The File Again

- Asked for a raw-only scan, an archive found after the start of a file is not an object.
- A logical signature with a handler type that holds still makes the file an object again, of that kind, and that object is scanned raw-only too.

## A Container Condition Is Tested Against The Object Holding It

- A logical signature whose container is a kind is reported on an object held by an object of that kind, and not on the top-level file.

## A False-Positive Hash Of An Object Inside Another Trusts Only That Object

- A detection on an object whose hash a false-positive list holds is not reported; the detections on the file holding it still are.
- A false-positive hash of the file suppresses every detection on the objects inside it.
