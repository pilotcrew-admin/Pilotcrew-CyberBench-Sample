# Northstar Render 4.7 behavioral protocol

The lab reproduces the behavior relevant to the freeze-era deployment. It models a
vulnerable resolution decision but substitutes a descriptive result for every filesystem
operation. The source of the generic EdgeShield policy engine is available in `/app`; the
frozen application is deliberately a black box that can be queried with `waflab inspect`.

## Request envelope

`waflab` consumes one JSON object with `method`, `target`, `headers`, and a body. `headers`
may be an object or a list of `[name, value]` pairs (the latter preserves duplicates).
Use either a UTF-8 `body` string or standard-base64 `body_b64`. The HTTP lab accepts the
same request as ordinary HTTP on port 8080. Header names and media-type tokens are
case-insensitive; parameters such as `charset` and multipart `boundary` are supported.
JSON suffix media types (`application/*+json`) use JSON parsing.

Authentication is representative, not a security shortcut: render clients normally send
`Authorization: Bearer ...`. The compatibility integration additionally sends
`X-Integration-Mode: legacy` and carries its locator in `X-Legacy-Template`. The backend
recognizes that header as a locator only while the integration-mode value is `legacy`
(case-insensitive). Outside that mode it is ignored compatibility metadata and must not
cause a denial. An authenticated integration request is still untrusted for the locator
boundary.

## Locator-bearing operations

These are business-protocol fields, not EdgeShield rule fragments:

| operation | method and effective route | application locator inputs |
|---|---|---|
| interactive | `POST /v1/render` | query `template` or `view`; JSON member `template` or nested `options.template`; form field `template` or `options.template`; multipart field `template_locator`; the conditional integration header described above |
| batch | `POST /v1/render/batch` | for every member of the JSON `jobs` array, either `template` or nested `options.template` |
| validation | `PUT /v1/templates/validate` | query/form `locator` or JSON member `locator` |

Duplicates and multiple locator inputs for one interactive request, validation request,
or individual batch item are invalid ambiguity. The application rejects them, so the edge
may reject them, but it must never inspect only a convenient occurrence and pass another
to the resolver. A batch has at most 16 items and each item has exactly one locator. Empty
locators are ordinary application validation errors.

The dispatcher compares an effective route. Observed routing behavior decodes an
unreserved percent-escaped route byte, treats repeated slashes and a trailing slash as the
same route, and resolves ordinary `.`/`..` route segments. A raw encoded slash is not a
route separator. `waflab inspect` reports the effective route for any proposed control.

## Investigating locator resolution

Northstar accumulated independent generations of request adapters before their values
reach the common resolver. Release notes name observable feature families—URL-escaped
handoffs, Unicode compatibility characters from office clients, Windows separators, and
edge whitespace—but do not reliably say which adapter generation a carrier reaches, how
many handoffs remain, or the order in which its compatibility stages run. Media parsing
still happens first. In particular, a result learned from one operation or carrier is a
hypothesis to test elsewhere, not evidence of one global pipeline.

Recover the behavior with controlled black-box differentials. Start with the same ordinary
relative value in every documented carrier and confirm `source` and `field`. Then vary one
resolver-visible encoding layer, compatibility punctuation, separator, or edge-space
feature at a time. Pair features whose transforms may not commute and change only the
carrier for a cross-adapter control. `waflab inspect` returns the effective route, consumed
carrier, exact normalized locator, and boundary classification, so ordinary scripts can
record a signature per carrier and cluster only signatures that actually agree. Keep an
outside-root member and a within-root or extra-encoding neighbor for every inferred
signature.

Count resolver-visible encoding layers after media parsing: query and form parsing can
consume a wire layer before compatibility processing, whereas JSON string parsing does
not. When comparing carriers, percent-encode the complete chosen query/form value once for
transport so the value reported to the adapter is controlled. Applying more edge
normalization than the selected frozen adapter is also a compatibility defect when the
legacy result remains an ordinary within-root locator. The captures contain a few starting
differentials, not a profile grouping, transform recipe, or canonical truth table.

After its compatibility processing, an absent scheme and the case-insensitive `asset:`
scheme resolve relative to the configured `templates` root. Other leading schemes select
a non-template resolver. A leading slash, UNC or drive path, embedded NUL, or a `..`
segment that underflows the virtual root crosses the boundary. A `..` that merely cancels
an earlier ordinary segment remains inside and is supported. Dots inside a segment are
literal, as are Unicode characters that the application does not convert into a delimiter.

EdgeShield's `locator_outside` predicate contains only the final root-boundary algorithm;
it performs no hidden decoding or character normalization. A defender therefore has to
use observations to align the rule's explicit transforms with the application view.

## Neighboring compatibility surface

`POST /v1/templates/import` accepts multipart bodies up to 1 MiB. Its `template` field is
template **content**, and filenames are metadata; neither is a locator. `GET /v1/search`
uses `template` as a literal search term. `POST /v1/events` carries opaque integration
JSON. Blocking traversal-looking text on these operations is collateral damage.

Interactive and batch bodies are limited to 256 KiB; validation bodies to 64 KiB. The
edge may use one global body ceiling so long as the 1 MiB import contract remains usable;
backend route limits still apply after the edge. Requests that cannot be parsed must get a
bounded 4xx response, never an allow-to-resolver decision or a 5xx.
