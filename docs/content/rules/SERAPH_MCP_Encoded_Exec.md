# MCP config decodes a payload into a shell or eval

## Threat

Encoding is a way to keep a command out of a casual read of a JSON file. The interesting event is not the presence of a long token. Tokens are normal. The interesting event is a decode step whose output is handed to a shell, or a decode call placed inside `eval` or `exec`.

## Why this rule

The rule requires the MCP server map and one of those two shapes. A long opaque string in an environment value, with no decode flag and no eval, is a negative fixture on purpose. The synthetic decode used in the fixtures is the ASCII sentence `echo seraph-inert`, so a reviewer can reverse it and see that the sample is inert.

## Limitations

A custom decoder, or a decode that writes a file instead of executing, does not match. A legitimate tool whose command line really does decode-and-exec will match and needs a human. The rule will not flag a blob that is never decoded in the file.
