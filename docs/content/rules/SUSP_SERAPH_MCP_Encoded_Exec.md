# MCP config decodes a payload into a shell or eval

## Threat

Encoding is a way to keep a command out of a casual read of a JSON file. The interesting event is not the presence of a long token. Tokens are normal. The interesting event is a decode step whose output is handed to a shell, or a decode call placed inside `eval` or `exec`.

## Why this rule

The rule requires the MCP server map and one of those two shapes. A long opaque string in an environment value, with no decode flag and no eval, is a negative fixture on purpose. The synthetic decode used in the fixtures is the ASCII sentence `echo seraph-inert`, so a reviewer can reverse it and see that the sample is inert. A decode piped into a bare interpreter, a decode inside a command substitution that a shell runs, and a decode written to a file that is run in the same string all match. Python's `a2b_base64` counts as a decoder.

## Limitations

A custom decoder, a decode written to a file that a separate process runs, or a decoder name assembled from pieces other than the `getattr` form does not match. A legitimate tool whose command line really does decode-and-exec will match and needs a human. The rule will not flag a blob that is never decoded in the file. A decode to a file, a chmod and then an interpreter started by name (exec node run.js) will miss, because telling the decoded file from another script needs a backreference.

## Triage

Decode the blob in a scratch buffer. The pack's own fixtures decode to an echo sentence. If the decoded text is a command the operator did not ask for, remove the entry.
