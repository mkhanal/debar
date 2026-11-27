> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Plain text

What signatures for text, and signatures for any kind of file, see of a text file beyond its own bytes, as a user of the supported signature format observes it.

## Text Is Matched Through Its Normalised Text

- A text file's normalised text is its bytes with letters lowercased, each run of whitespace written as one space, and control bytes and bytes at or above `0x80` left out.
- Signatures for text and signatures for any kind of file are matched against the normalised text, and a detection there is reported on the text file.
- A signature for text is not matched against the text file's own bytes.
- An offset in a signature counts from the start of the normalised text.

## A Hash Of The Normalised Text Detects The Text File

- A hash signature listing the normalised text's hash and size is reported on the text file.

## Whitespace Starts Afresh Every 131,072 Bytes Plus The Longest Part Of A Signature For Text

- The run of whitespace in progress ends after every 131,072 bytes of text, plus the length of the longest part of any signature for text, so a run across that point is written as two spaces.

## Text Of More Than 20 MiB Is Not Normalised

- A text file of more than 20 MiB is matched only through its own bytes.

## Text Found To Be A Web Page Is Not Matched Through Normalised Text

- A text file retyped as HTML while its own bytes are matched has no normalised text matched.
