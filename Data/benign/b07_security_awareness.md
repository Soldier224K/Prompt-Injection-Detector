# Security awareness: handling untrusted content

Documents, web pages, and email attachments may contain text written to
manipulate an automated assistant. Treat all third-party content as data, not
as a source of authority.

Practical controls:

- Keep the assistant's operating policy in a trusted configuration layer.
- Label retrieved passages with their origin and trust level.
- Require human approval before payment, deletion, or outbound network actions.
- Log tool calls and review unusual sequences after the fact.
- Apply least privilege to service accounts and API tokens.

This guidance is descriptive. It does not ask the reader to execute any command
or to change an assistant's behavior.
