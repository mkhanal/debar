> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Start and memory

How soon Debar is ready to scan and how much memory it holds, with every pinned database compiled into its image and default settings.

## Debar Is Ready To Scan Within 50 ms Of Starting, With Every Pinned Database In Its Image

- Ready means the image is mapped and its header checked, so the first object can be read.
- Starting, becoming ready and scanning one small file take at most 50,000,000 user-space instructions: the 50 ms budget at one instruction per nanosecond.
- Once ready, at most 512 KiB of the image is resident.
- Wall-clock medians are measured and recorded; they do not gate a change.

## Debar Holds At Most 64 MiB Of Private Memory Once Ready

- Private memory is anonymous plus privately dirtied memory, excluding the image mapping.
- It is measured once ready, before the first object is read.

## Scanning One File Holds At Most 32 MiB Of Memory

- It is measured as the peak heap while scanning a file of 100 MiB whose regular expressions are matched over the whole of it, less the peak heap when the file is too small to be scanned.
