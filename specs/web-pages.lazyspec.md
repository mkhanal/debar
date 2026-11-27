> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Web pages

What signatures for web pages, and signatures for any kind of file, see of a file typed as HTML, as a user of the supported signature format observes it: two views of the page, one without its comments and one without its tags.

## A Web Page Is Matched Through Its Page Without Comments And Its Page Without Tags

- Signatures for web pages and signatures for any kind of file are matched against the page without comments, then against the page without tags, and a detection in either is reported on the page.
- The page's own bytes are not matched.
- An offset in a signature counts from the start of the view it is matched in.

## The Page Without Comments Is The Page Lowercased, With Comments Left Out And References Decoded

- Letters outside character references are lowercased, and each run of whitespace in text is one space.
- A comment, from `<!` to the first `>` after it, is left out.
- Character references such as `&amp;`, `&#65;` and `&#x42;` are decoded.
- Inside a script or a style, whitespace is left out and `'` is written as `"`.

## The Page Without Tags Holds The Page's Text And Its Links

- Text outside tags, scripts and styles is kept, lowercased, and each run of tags, whitespace and character references is one space.
- The `href` of a link and the `src` of an image are written as they stand in the page, each followed by a space.

## Bytes At Or Above 0x80 Reach The Page Without Tags As The Supported Format Writes Them

- Consecutive bytes at or above `0x80` are taken in groups of up to three.
- A group's first byte is written, then its second byte twice, so `é` (`c3 a9`) is written `c3 c3` and `中` (`e4 b8 ad`) is written `e4 b8 b8`.
- The page without comments keeps those bytes as they are.

## A Hash Of A Page's View Detects The Page

- A hash signature listing the hash and size of the page without comments, or of the page without tags, is reported on the page.

## A Page Of More Than 40 MiB Is Not Matched At All

- A file typed as HTML of more than 40 MiB is reported with no detection, whatever signatures its bytes hold.

## A Page Of More Than 8 MiB Is Matched Only Through Its Page Without Comments

- A file typed as HTML of more than 8 MiB is not matched through its page without tags.

## Text Found To Be A Web Page Is Matched Through Its Views

- A text file retyped as HTML while its own bytes are matched is then matched through its page without comments and its page without tags.

## Without Every Match, A Detection In The Page Without Comments Ends The Page's Matching

- Without every match, a page whose page without comments holds a detection is not matched through its page without tags.
