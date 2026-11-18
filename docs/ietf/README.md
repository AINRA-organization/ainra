<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Internet-Drafts

| Draft | Status |
|---|---|
| [`draft-georgiev-agent-key-status-00`](draft-georgiev-agent-key-status-00.md) | Written 2026-10-29; brought up to date 2026-11-18 (RSA keys, issuer links, keys in certificates, canonical bytes, actions in flight, the Web Bot Auth drafts). Not submitted. |

**draft-georgiev-agent-key-status** specifies the link record (D-078) for any implementer: request links and issuer
links (D-110), five key algorithms (Ed25519, ES256K, ES256, RS256, PS256; D-082, D-108, D-112), keys in certificates,
proof of control by the linked key, the three kinds of revocation, the fixed verification order, canonical bytes
(D-118), what revocation does to actions already in flight, and reuse of the IETF Token Status List for the status
itself. It is aimed at the OAuth, Web Bot Auth and agentproto working groups, as an individual submission.

The source is kramdown-rfc markdown. To produce the XML (what the datatracker takes) and the text and HTML versions,
which `xml2rfc` also checks:

```
gem install kramdown-rfc && kramdown-rfc docs/ietf/draft-georgiev-agent-key-status-00.md > draft-georgiev-agent-key-status-00.xml
python3 -m venv ~/.venvs/ietf && ~/.venvs/ietf/bin/pip install xml2rfc
~/.venvs/ietf/bin/xml2rfc --text --html draft-georgiev-agent-key-status-00.xml
```

On 18 November 2026 both steps ran with no warning and every line of the text version is within 72 characters. The
datatracker runs `idnits` itself on upload.

Submitting is the author's step, through the IETF datatracker. Nothing here has been sent anywhere.
