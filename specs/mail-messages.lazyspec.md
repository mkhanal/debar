> **lazyspec.** Humans edit freely. Agents change this only through
> `/lazyspec`, with its tests, in one edit.
>
> Each `##` heading is one requirement. Its test repeats that heading
> as its own name — to find it, search the tests for that text.

# Mail messages

What a scan finds inside a mail message (a file typed as mail or as MHTML, or a mailbox of such messages), as a user of the supported signature format observes it.

## A Mail Message's Parts Are Scanned As Objects Of Their Own

- Each part of a multipart message, at any depth of nested multipart sections, is an object one level below the message, typed from its bytes.
- A message with no multipart section is one object below it: its body.
- A detection in a part is reported on the part.

## A Mail Part Is Scanned As Its Decoded Bytes

- A part sent in base64 or quoted-printable is the bytes those decode to.
- A part sent unencoded is its lines, each ended by one line feed, whatever line end the message used.
- A part with a filename and no transfer encoding but 7bit is scanned twice: as written, and as its lines decoded as base64.

## A Message Attached To A Message Is Scanned As A Message Of Its Own

- A `message/rfc822` part whose body names a transfer encoding other than 7bit is an object typed as mail, and its own parts are objects below it.

## A Message Without A Content Header Or Sender Yields No Parts

- A message whose headers hold no `Content-Type`, `Content-Transfer-Encoding`, `Content-Disposition`, `From`, `Received` or `De` header is matched on its own bytes only.

## Each Message Of A Mailbox Is Opened

- In a file starting `From `, a line starting `From ` after an empty line starts a new message, and each message's parts are objects below the file.

## A Uuencoded Block In A Message Body Is Scanned As Its Decoded Bytes

- A body line `begin` followed by a three-digit mode and a name starts a uuencoded block, which is an object of its decoded bytes, and is left out of the body's own object.

## Text Found To Be Mail Is Matched As Mail

- Text retyped as mail while its own bytes are matched has its parts scanned, and its bytes are matched against signatures for mail.
