> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# ZIP archives

What a scan finds inside a ZIP file or an Office Open XML document (which is a ZIP file), and how each member and entry is tested, as a user of the supported signature format observes it.

## A ZIP's Members Are Scanned As Objects Of Their Own

- Each stored or deflated member is an object one level below the archive, holding the member's own bytes and typed from them.
- A detection in a member is reported on the member.
- A ZIP inside a member is opened in turn, its members one level deeper again.

## An Office Open XML Document Is Typed As Its Kind And Its Members Are Scanned

- A ZIP whose first entries name a `word/`, `xl/` or `ppt/` entry is typed as that kind of document.
- Its members are objects of their own, as a ZIP's are.

## Each ZIP Entry Is Tested Against Container Signatures By Its Name, Sizes, Encryption And Position

- The name tested is the entry's full name as stored, folders included.
- The sizes and the encryption flag tested are those the archive declares, and the position counts entries from 1.
- The container tested is the archive, of its own kind, and a detection is reported on it.

## A ZIP Member Over The File-Size Limit Is Cut To It

- A deflated member that decodes to more than the file-size limit is cut to the largest multiple of 8,192 bytes within it, and its first bytes are scanned.

## A ZIP Stops Extracting At The File-Count Limit

- No more files are scanned than the file-count limit, the archive itself among them, and the members scanned are the first in the archive.

## A ZIP Inside Another File Is An Object For Each Of Its Local Headers

- Each local header after the start of a file that is not itself a ZIP makes a ZIP object of that one header and its data, holding its member.
- There are as many such objects as local headers, up to the file-count limit.

## A ZIP With A Duplicate Or Overlapping Record Has No Member Scanned

- A member listed twice in the central directory leaves every member of the archive unscanned.
- So do one to five records overlapping the record before them.

## More Than Five Overlapping ZIP Records Raise An Alert And Are Read From Their Local Headers

- Such an archive is reported as `Heuristics.Zip.OverlappingFiles`, potentially unwanted.
- Its members are then found from the local headers at the start of the archive alone.

## A Damaged ZIP Yields The Members Its Local Headers Still Hold

- With no central directory, every complete member is found from its local header.
- A member cut short by the end of the file is not scanned; the members before it are.
- A deflated member whose data is corrupt is not scanned.

## An Encrypted ZIP Member Is Scanned As The Bytes It Stores

- With no password to try, a stored member flagged as encrypted is scanned as the bytes the archive holds for it.
